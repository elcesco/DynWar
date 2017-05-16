#pragma once

#include <netinet/ip.h>
//#include <netinet/in.h>

class IODevice
{
public:
	IODevice();
	virtual ~IODevice();
	virtual int open(bool dir) = 0;
	virtual int close() = 0;
//	virtual bool hasData() = 0;
//	virtual bool isOnline() = 0;
	virtual int receive() = 0;
        virtual int send(const ip *) = 0;
};

