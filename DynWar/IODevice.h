#pragma once
class IODevice
{
public:
	IODevice();
	virtual ~IODevice();
	virtual int open();
	virtual int close();
};

