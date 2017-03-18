#pragma once
#include "IODevice.h"
#include "main.h"

class DevicePCAPOffline :
	public IODevice
{
public:
	DevicePCAPOffline();
	~DevicePCAPOffline();
	void getInfo();
};

