#pragma once

#include <cstdio>
#include <iostream>
#include <memory>
#include <string>

#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "cuckoofilter-master/src/cuckoofilter.h"

#include"DynWarden.h"
#include "ConfigurationManager.h"

#include"IODevice.h"
#include "DevicePCAPOffline.h"
#include "DevicePCAPOnline.h"

int main(int argc, char ** argv);


