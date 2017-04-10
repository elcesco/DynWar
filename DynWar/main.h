#pragma once

#include <stdio.h>

#include <cstdio>
#include <iostream>
#include <memory>
#include <string>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

//#include "libcuckoo/cuckoohash_map.hh"

#include"IODevice.h"
#include"DynWarden.h"
#include "ConfigurationManager.h"
#include "DevicePCAPOffline.h"
#include "DevicePCAPOnline.h"

int main(int argc, char ** argv);


