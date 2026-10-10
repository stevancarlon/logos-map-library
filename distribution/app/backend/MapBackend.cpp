// SPDX-License-Identifier: MIT OR Apache-2.0
#include "MapBackend.h"
#include <QDir>
#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSet>
#include <QStandardPaths>
#include <QUrl>
#include <dlfcn.h>
#include <stdexcept>
namespace {
void anchor() {}
void require(bool ok, const char *text) {
  if (!ok)
    throw std::runtime_error(text);
}
} // namespace
MapBackend::MapBackend(QObject *parent)
    : QObject(parent), m_settings("LogosPrizeSuite", "MapLibraryV03") {
  connect(&m_process, &QProcess::readyReadStandardOutput, this,
          &MapBackend::collect);
  connect(&m_process, &QProcess::readyReadStandardError, this,
          &MapBackend::collect);
  connect(&m_process, &QProcess::errorOccurred, this,
          [this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart) {
              m_running = false;
              m_error = "Cannot start the bundled maps CLI.";
            }
          });
  connect(&m_process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
          this, [this](int code, QProcess::ExitStatus status) {
            collect();
            m_running = false;
            if (!m_error.isEmpty())
              return;
            if (code != 0 || status != QProcess::NormalExit) {
              m_error = QString::fromUtf8(m_stderr).left(2000);
              if (m_error.isEmpty())
                m_error = "Map operation failed.";
              return;
            }
            QJsonParseError error;
            auto doc = QJsonDocument::fromJson(m_stdout, &error);
            if (error.error != QJsonParseError::NoError || !doc.isObject()) {
              m_error = "Invalid response from maps CLI.";
              return;
            }
            m_result = doc.object();
            if (m_kind == "discover") {
              m_result["checked_at"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
              m_settings.setValue("source_catalog", QJsonDocument(m_result).toJson(QJsonDocument::Compact));
              m_settings.sync();
              if (m_settings.status() != QSettings::NoError)
                m_error = "Source discovery completed, but its cache could not be saved.";
            }
            if (m_result["snapshot"].isObject())
              saveSnapshot(m_result["snapshot"].toObject());
          });
}
MapBackend::~MapBackend() {
  if (m_process.state() != QProcess::NotRunning) {
    m_process.kill();
    m_process.waitForFinished(1000);
  }
}
void MapBackend::saveSnapshot(const QJsonObject &snapshot) {
  auto saved = QJsonDocument::fromJson(m_settings.value("stored_snapshots").toByteArray()).array();
  for (const auto &row : saved) if (row.toObject() == snapshot) return;
  saved.append(snapshot);
  m_settings.setValue("stored_snapshots", QJsonDocument(saved).toJson(QJsonDocument::Compact));
  m_settings.sync();
  if (m_settings.status() != QSettings::NoError)
    m_error = "Upload completed, but its local record could not be saved. Keep the CID shown below.";
}
void MapBackend::collect() {
  m_stdout += m_process.readAllStandardOutput();
  m_stderr += m_process.readAllStandardError();
  if (m_kind == "store_bulk") {
    int newline;
    while ((newline = m_stderr.indexOf('\n')) >= 0) {
      const auto line = m_stderr.left(newline);
      const auto object = QJsonDocument::fromJson(line).object();
      if (!object["progress"].isObject()) break;
      m_stderr.remove(0, newline + 1);
      const auto outcome = object["progress"].toObject();
      if (m_outcomes.size() >= 72) { m_error = "Bulk response exceeded its limit."; m_process.kill(); break; }
      m_outcomes.append(outcome);
      if (outcome["state"] == "stored" && outcome["snapshot"].isObject())
        saveSnapshot(outcome["snapshot"].toObject());
    }
  }
  if (m_stdout.size() > 1024 * 1024 || m_stderr.size() > 16384) {
    m_error = "Operation response exceeded its limit.";
    m_process.kill();
    m_stdout.clear();
    m_stderr.clear();
  }
}
QString MapBackend::executable() const {
  Dl_info info{};
  if (dladdr(reinterpret_cast<void *>(&anchor), &info)) {
    auto path = QFileInfo(QString::fromLocal8Bit(info.dli_fname))
                    .absoluteDir()
                    .filePath("bin/maps-v03");
    if (QFileInfo(path).isExecutable())
      return path;
  }
  return QStringLiteral(PRIZE_MAPS_BIN);
}
QJsonObject MapBackend::state() const {
  return {{"ok", true},
          {"running", m_running},
          {"kind", m_kind},
          {"result", m_result},
          {"bulk_outcomes", m_outcomes},
          {"source_catalog", QJsonDocument::fromJson(m_settings.value("source_catalog").toByteArray()).object()},
          {"stored_snapshots", QJsonDocument::fromJson(m_settings.value("stored_snapshots").toByteArray()).array()},
          {"error", m_error},
          {"rpc", m_settings.value("rpc", "http://127.0.0.1:3040").toString()},
          {"program", m_settings.value("program").toString()},
          {"storage",
           m_settings.value("storage", "http://127.0.0.1:8080/api/storage/v1")
               .toString()}};
}
QString MapBackend::dispatch(const QString &text) {
  try {
    require(text.size() < 65536, "Request exceeds limit");
    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(text.toUtf8(), &error);
    require(error.error == QJsonParseError::NoError && doc.isObject(),
            "Invalid request");
    return QString::fromUtf8(
        QJsonDocument(execute(doc.object())).toJson(QJsonDocument::Compact));
  } catch (const std::exception &e) {
    return QString::fromUtf8(
        QJsonDocument(
            QJsonObject{{"ok", false}, {"error", QString::fromUtf8(e.what())}})
            .toJson(QJsonDocument::Compact));
  }
}
QJsonObject MapBackend::execute(const QJsonObject &r) {
  const auto op = r["op"].toString();
  if (op == "state")
    return state();
  if (op == "settings") {
    require(!m_running,
            "Wait for the current operation before changing connections");
    for (const auto &key : {"rpc", "storage"}) {
      auto value = r[key].toString().trimmed();
      QUrl url(value);
      require(
          url.isValid() &&
              (url.scheme() == "http" || url.scheme() == "https") &&
              !url.host().isEmpty() && url.userInfo().isEmpty() &&
              !url.hasQuery() && !url.hasFragment(),
          "Use an HTTP(S) node URL without credentials, query, or fragment");
    }
    const auto program = r["program"].toString().trimmed();
    require(
        program.isEmpty() ||
            QRegularExpression("^[1-9A-HJ-NP-Za-km-z]{32,44}$").match(program).hasMatch(),
        "Use the deployed v0.3 registry account address");
    for (const auto &key : {"rpc", "program", "storage"}) {
      m_settings.setValue(key, r[key].toString().trimmed());
    }
    m_settings.sync();
    m_result = {};
    m_error.clear();
    m_kind.clear();
    return state();
  }
  if (op == "cancel") {
    if (m_running) {
      m_error = "Operation canceled. A completed upload may still exist on "
                "Storage; no registration was submitted.";
      m_process.kill();
    }
    return state();
  }
  require(!m_running, "Wait for the current operation or cancel it");
  QStringList args;
  if (op == "catalog") {
    args = {"catalog"};
  } else if (op == "discover") {
    args = {"discover-versions"};
  } else if (op == "store_bulk") {
    require(!m_settings.value("program").toString().isEmpty(), "Configure the registry first");
    require(r["items"].isArray(), "Choose regions to host");
    const auto items = r["items"].toArray();
    require(!items.isEmpty() && items.size() <= 72, "Choose between one and 72 regions");
    const auto limit = r["limit"].toString();
    bool valid = false;
    const auto bytes = limit.toULongLong(&valid);
    require(valid && bytes > 0 && bytes <= 100000000000ULL, "Invalid per-region size limit");
    // SDK validates the complete selection and dates before any network upload.
    const auto encoded = QJsonDocument(items).toJson(QJsonDocument::Compact);
    m_bulkFile.close();
    m_bulkFile.remove();
    m_bulkFile.setFileTemplate(QDir::tempPath() + "/maps-bulk-XXXXXX.json");
    require(m_bulkFile.open(), "Cannot create bulk selection file");
    require(m_bulkFile.write(encoded) == encoded.size() && m_bulkFile.flush(), "Cannot save bulk selection");
    const auto scratch = QStandardPaths::writableLocation(QStandardPaths::CacheLocation) + "/logos-prize-maps";
    require(QDir().mkpath(scratch), "Cannot create upload scratch directory");
    args = {"store-bulk", m_settings.value("rpc").toString(), m_settings.value("program").toString(),
            m_settings.value("storage").toString(), m_bulkFile.fileName(), limit, scratch};
  } else if (op == "updates") {
    const auto program = m_settings.value("program").toString();
    require(!program.isEmpty(), "Configure the deployed map registry in Connections first");
    require(r["regions"].isArray(), "Select regions to check");
    const auto regions = r["regions"].toArray();
    require(!regions.isEmpty() && regions.size() <= 72, "Select between one and 72 regions");
    QFile catalog(":/maps/catalog.json");
    require(catalog.open(QIODevice::ReadOnly), "Catalog unavailable");
    QSet<QString> allowed, seen;
    for (const auto &item : QJsonDocument::fromJson(catalog.readAll()).object()["canonical_regions"].toArray())
      allowed.insert(item.toObject()["path"].toString());
    for (const auto &item : regions) {
      const auto region = item.toString();
      require(allowed.contains(region) && !seen.contains(region), "Select distinct supported regions");
      seen.insert(region);
    }
    const auto pages = r["max_pages"].toInt(-1);
    require(pages >= 1 && pages <= 4096, "Registry scan limit must be between 1 and 4096 pages");
    args = {"updates", m_settings.value("rpc").toString(), program,
            QString::fromUtf8(QJsonDocument(regions).toJson(QJsonDocument::Compact)), QString::number(pages)};
  } else if (op == "query") {
    const auto program = m_settings.value("program").toString();
    require(!program.isEmpty(),
            "Configure the deployed map registry ID in Connections first");
    const auto region = r["region"].toString();
    require(region.size() < 200 && !region.isEmpty(), "Select a region");
    const auto page = r["page"].toInt(-1);
    require(page >= 0, "Invalid page");
    args = {"registry-page", m_settings.value("rpc").toString(),
            program,         QString::number(page),
            "region",        region};
  } else if (op == "verify" || op == "upload" || op == "download" || op == "download_snapshot" ||
             op == "fetch" || op == "host_local" || op == "host_fetch") {
    const auto checksum = r["md5"].toString().trimmed();
    require(
        op == "fetch" || op == "host_local" || op == "host_fetch" || op == "download_snapshot" ||
            QRegularExpression("^[a-fA-F0-9]{32}$").match(checksum).hasMatch(),
        "Enter the 32-character MD5 checksum");
    const auto limit = r["limit"].toString();
    bool ok = false;
    const auto bytes = limit.toULongLong(&ok);
    require(ok && bytes > 0 && bytes <= 100000000000ULL,
            "Choose a byte limit between 1 and 100 GB");
    QString path = r["file"].toString();
    if (path.startsWith("file:"))
      path = QUrl(path).toLocalFile();
    require(!path.isEmpty() && QFileInfo(path).isAbsolute(),
            "Choose an absolute local file path");
    if (op == "fetch" || op == "host_local" || op == "host_fetch") {
      const auto region = r["region"].toString();
      QFile catalog(":/maps/catalog.json");
      require(catalog.open(QIODevice::ReadOnly), "Catalog unavailable");
      bool known = false;
      for (const auto &item : QJsonDocument::fromJson(catalog.readAll())
                                  .object()["canonical_regions"]
                                  .toArray()) {
        if (item.toObject()["path"].toString() == region)
          known = true;
      }
      require(known, "Select a supported region from the Library first");
      if (op == "fetch") args = {"fetch-region", region, path, limit};
      else {
        const auto program = m_settings.value("program").toString();
        require(!program.isEmpty(), "Configure the map registry in Connections first");
        const auto scratch = QStandardPaths::writableLocation(QStandardPaths::CacheLocation) + "/logos-prize-maps";
        require(QDir().mkpath(scratch), "Cannot create upload scratch directory");
        const auto version = r["version"].toString().trimmed();
        require(version.isEmpty() || QRegularExpression("^20[0-9]{6}$").match(version).hasMatch(), "Use YYYYMMDD for the source snapshot date, or leave it empty for latest");
        args = {op == "host_local" ? "host-local" : "host-fetch", m_settings.value("rpc").toString(), program,
                m_settings.value("storage").toString(), region, path, limit, scratch, version};
      }
    } else if (op == "download_snapshot") {
      require(r["snapshot"].isObject() && !r["snapshot"].toObject().isEmpty(),
              "Choose a registry snapshot first");
      const auto json = QJsonDocument(r["snapshot"].toObject()).toJson(QJsonDocument::Compact);
      require(json.size() <= 32768, "Snapshot exceeds size limit");
      args = {"download-snapshot",
              m_settings.value("storage", "http://127.0.0.1:8080/api/storage/v1").toString(),
              QString::fromUtf8(json), limit, path};
    } else if (op == "verify")
      args = {"verify", path, checksum, limit};
    else if (op == "upload") {
      auto scratch =
          QStandardPaths::writableLocation(QStandardPaths::CacheLocation) +
          "/logos-prize-maps";
      require(QDir().mkpath(scratch), "Cannot create upload scratch directory");
      args = {
          "upload",
          m_settings.value("storage", "http://127.0.0.1:8080/api/storage/v1")
              .toString(),
          path,
          checksum,
          limit,
          scratch};
    } else {
      const auto cid = r["cid"].toString();
      require(QRegularExpression("^[A-Za-z0-9]{1,128}$").match(cid).hasMatch(),
              "Invalid Storage CID");
      args = {
          "download",
          m_settings.value("storage", "http://127.0.0.1:8080/api/storage/v1")
              .toString(),
          cid,
          checksum,
          limit,
          path};
    }
  } else
    throw std::runtime_error("Unknown map operation");
  require(QFileInfo(executable()).isExecutable(),
          "Build or install the maps CLI before using this action");
  m_result = {};
  if (op == "store_bulk") m_outcomes = {};
  m_error.clear();
  m_stdout.clear();
  m_stderr.clear();
  m_kind = op;
  m_running = true;
  m_process.start(executable(), args);
  return state();
}
