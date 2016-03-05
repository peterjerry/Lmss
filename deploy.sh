#!/bin/sh

test -d '/usr/local/lmss' || mkdir -p '/usr/local/lmss'
test -d '/usr/local/lmss/sbin' || mkdir -p '/usr/local/lmss/sbin'
test -d '/usr/local/lmss/core' || mkdir -p '/usr/local/lmss/core'
test -d '/usr/local/lmss/conf' || mkdir -p '/usr/local/lmss/conf'

test ! -f '/usr/local/lmss/sbin/lmss' || mv '/usr/local/lmss/sbin/lmss' '/usr/local/lmss/sbin/lmss.old'
cp objs/nginx '/usr/local/lmss/sbin/lmss'

cp conf/koi-win '/usr/local/lmss/conf'
cp conf/koi-utf '/usr/local/lmss/conf'
cp conf/win-utf '/usr/local/lmss/conf'

test -f '/usr/local/lmss/conf/mime.types' || cp conf/mime.types '/usr/local/lmss/conf'
cp conf/mime.types '/usr/local/lmss/conf/mime.types.default'
test -f '/usr/local/lmss/conf/fastcgi_params' || cp conf/fastcgi_params '/usr/local/lmss/conf'
cp conf/fastcgi_params '/usr/local/lmss/conf/fastcgi_params.default'
test -f '/usr/local/lmss/conf/fastcgi.conf' || cp conf/fastcgi.conf '/usr/local/lmss/conf'
cp conf/fastcgi.conf '/usr/local/lmss/conf/fastcgi.conf.default'
test -f '/usr/local/lmss/conf/stat.xsl' || cp conf/stat.xsl '/usr/local/lmss/conf'
cp conf/stat.xsl '/usr/local/lmss/conf/stat.xsl.default'
cp conf/nginx.conf '/usr/local/lmss/conf/lmss.conf'
cp conf/lmss.info '/usr/local/lmss/conf/'
cp conf/lmds.info '/usr/local/lmss/conf/'
cp conf/startup '/usr/local/lmss/'

test -d '/usr/local/lmss/logs' || mkdir -p '/usr/local/lmss/logs'
test -d '/usr/local/lmss/logs' || mkdir -p '/usr/local/lmss/logs'
test -d '/usr/local/lmss/html' || cp -R html '/usr/local/lmss'
test -d '/usr/local/lmss/logs' || mkdir -p '/usr/local/lmss/logs'
