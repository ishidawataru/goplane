#!/bin/bash
gobgpd -f /root/shared_volume/gobgpd.conf -l debug -p > /root/shared_volume/gobgpd.log 2>&1
