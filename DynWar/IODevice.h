#pragma once

class IODevice
{
public:
	IODevice();
	virtual ~IODevice();
	virtual int open() = 0;
	virtual int close() = 0;
//	virtual bool hasData() = 0;
//	virtual bool isOnline() = 0;
	virtual int run() = 0;
};

