// SPDX-License-Identifier: MIT OR Apache-2.0
#pragma once
#include <QJsonObject>
#include <QObject>
#include <QProcess>
#include <QSettings>
#include <QTemporaryFile>
#include <QJsonArray>
class MapBackend : public QObject {
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.logos.prizes.maps/1.0" FILE
                        "../metadata.json")
public:
  explicit MapBackend(QObject *parent = nullptr);
  ~MapBackend() override;
  Q_INVOKABLE QString dispatch(const QString &request);

private:
  QProcess m_process;
  QTemporaryFile m_bulkFile;
  QJsonArray m_outcomes;
  void saveSnapshot(const QJsonObject &snapshot);
  QSettings m_settings;
  QByteArray m_stdout, m_stderr;
  QJsonObject m_result;
  QString m_error, m_kind;
  bool m_running = false;
  QString executable() const;
  QJsonObject state() const;
  QJsonObject execute(const QJsonObject &request);
  void collect();
};
