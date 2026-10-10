#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Linux regression: real registry lookup and hosted download with external egress denied."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
from urllib.parse import urlsplit

GUARD = r'''
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int connect(int fd, const struct sockaddr *a, socklen_t n) {
  int allowed = a && (a->sa_family == AF_UNIX);
  if (a && a->sa_family == AF_INET && n >= sizeof(struct sockaddr_in))
    allowed = ntohl(((const struct sockaddr_in *)a)->sin_addr.s_addr) == 0x7f000001;
  if (a && a->sa_family == AF_INET6 && n >= sizeof(struct sockaddr_in6))
    allowed = IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)a)->sin6_addr);
  if (!allowed) { fputs("MAPS_EGRESS_DENIED connect\n", stderr); errno=ENETUNREACH; return -1; }
  int (*real_connect)(int,const struct sockaddr *,socklen_t)=dlsym(RTLD_NEXT,"connect");
  return real_connect(fd,a,n);
}
int getaddrinfo(const char *node,const char *service,const struct addrinfo *h,struct addrinfo **r) {
  if (node && strcmp(node,"127.0.0.1") && strcmp(node,"::1") && strcmp(node,"localhost")) {
    fputs("MAPS_EGRESS_DENIED DNS\n",stderr); return EAI_NONAME;
  }
  int (*real_getaddrinfo)(const char *,const char *,const struct addrinfo *,struct addrinfo **)=dlsym(RTLD_NEXT,"getaddrinfo");
  return real_getaddrinfo(node,service,h,r);
}
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('rpc','program','storage','snapshot','cli'):
        parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    if platform.system()!='Linux':parser.error('This egress guard is Linux-specific')
    for endpoint in (args.rpc,args.storage):
        url=urlsplit(endpoint)
        if url.scheme!='http' or url.hostname!='127.0.0.1' or not url.port:
            parser.error('Only disposable loopback fixtures are accepted')
    snapshot=json.loads(args.snapshot)
    cli=Path(args.cli).resolve()
    with tempfile.TemporaryDirectory(prefix='maps-hosted-offline-') as directory:
        scratch=Path(directory);source=scratch/'guard.c';source.write_text(GUARD)
        guard=scratch/'guard.so'
        subprocess.run(['cc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(source),'-ldl','-o',str(guard)],check=True)
        env={k:v for k,v in os.environ.items() if k.lower() not in ('http_proxy','https_proxy','all_proxy','no_proxy')}
        env['LD_PRELOAD']=str(guard)
        def run(arguments):
            return subprocess.run([str(cli),*arguments],env=env,text=True,capture_output=True,timeout=300)
        # Prove the guard is active against a real source-only code path.
        blocked=run(['latest-version',snapshot['region']])
        assert blocked.returncode!=0 and 'MAPS_EGRESS_DENIED' in blocked.stderr,blocked.stderr
        catalog=run(['catalog']);assert catalog.returncode==0,catalog.stderr
        query=run(['registry-page',args.rpc,args.program,'0','cid',snapshot['cid']])
        assert query.returncode==0 and 'MAPS_EGRESS_DENIED' not in query.stderr,query.stderr
        page=json.loads(query.stdout)
        assert any(r['snapshot']==snapshot for r in page['records']),page
        destination=scratch/'download.osm.pbf'
        download=run(['download-snapshot',args.storage,args.snapshot,str(snapshot['bytes']),str(destination)])
        assert download.returncode==0 and 'MAPS_EGRESS_DENIED' not in download.stderr,download.stderr
        with destination.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        assert destination.stat().st_size==snapshot['bytes'] and digest==bytes(snapshot['sha256']).hex()
        print(json.dumps({'result':'passed','source_request_blocked':True,'registry_query_without_external_egress':True,
            'hosted_download_without_external_egress':True,'bytes':snapshot['bytes'],'sha256':digest,
            'cli_sha256':hashlib.sha256(cli.read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'guard_sha256':hashlib.sha256(GUARD.encode()).hexdigest(),
            'scope':'Linux dynamically linked CLI under an LD_PRELOAD regression guard; real isolated registry and Storage supplied by caller. Not a security sandbox or proof of public availability.'}))

if __name__=='__main__':main()
