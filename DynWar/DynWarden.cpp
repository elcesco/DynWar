#include "DynWarden.h"

DynWarden::DynWarden()
{
	std::cout << "called DynWarden constructor ..." << std::endl;


}


DynWarden::~DynWarden()
{
	std::cout << "called DynWarden destructor." << std::endl;

}


int DynWarden::start()
{
	std::cout << "starting dynamic warden..." << std::endl;

	// Get configuration and settings
	//FIXME

	// Initialize cukoo filters
	// a) innocent flows
	// b) suspicious flows
	//FIXME

	// initialize input
	IODevice* inputdevice = (IODevice*)(new DevicePCAPOffline());
	inputdevice->open();

	// initialize output
	//IODevice* outputdevice = (IODevice*)(new DevicePCAPOffline());
	//outputdevice->open();
	//FIXME

	// start processing incomming packets
	int counter = 0;
	do {
		// is packet available ?
		if (inputdevice->hasData()) {

			// get packet
			inputdevice->getData();

			// Calculate Flow ID
			//FIXME

			// Is this an innocent flow ID ?
			//FIXME

			// Is this a known suspicious flow id ?
			//FIXME

			// Which sampling strategy to use ?
			//FIXME

			// Do we sample this packet ?
			//FIXME

			// Is there another packet comming ? or are we done ?
			//std::cout << counter << ": Looping thru the packets." << std::endl;
			//FIXME
			counter++;

		}

	} while (inputdevice->isOnline());

	// Close input and outout devices
	inputdevice->close();
	//outputdevice->close();

	// Start analysis of the experiment
	//FIXME

	return 0;
}
