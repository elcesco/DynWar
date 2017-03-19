#include "main.h"

using namespace std;

int main(int argc, char** argv) {

	//Get the main class initialized
	std::cout << "main: starting ..." << std::endl;

	// Reading the command line arguments and ensure they are complete and valid
	auto_ptr<ConfigurationManager> _config(ConfigurationManager::getInstance());
	if (_config->init(argc, argv)) {

		//Get the main class initialized
		unique_ptr<DynWarden> dw_main(new DynWarden());

		// declare ourselves as highest priority process and switch off any disturbance.
		// FIXME

		// get the experiment started
		dw_main->start();

	}
	else {
		cerr << "main: Failed to parse commandline arguments." << endl;
	}

	std::cout << "main: done." << std::endl;

	return 0;
}