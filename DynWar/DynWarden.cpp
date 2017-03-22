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

	// Initialize cukoo filters - Create a cuckoo filter where each item is of 
	// type size_t and use 12 bits for each item:
	//size_t total_items = 100000;
	//CuckooFilter<size_t, 12> filter(total_items);

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
			inputdevice->receive();

			// Calculate Flow ID
			//FIXME

			// Is this an innocent flow ID ?
			//FIXME

			// Is this a known suspicious flow id ?
			//FIXME

			// Which sampling strategy to use ?
			//FIXME
			bool sampling = true;

			// Do we sample this packet ?
			if (sampling) {
				
				// Insert new flow ID to the suspicious cuckoo filter
				//size_t num_inserted = 0;
				//for (size_t i = 0; i < total_items; i++, num_inserted++) {
				//	if (filter.Add(i) != cuckoofilter::Ok) {
				//		break;
				//	}
				//}
			}

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

void DynWarden::receive()
{
}
