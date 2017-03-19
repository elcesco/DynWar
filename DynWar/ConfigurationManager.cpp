#include "ConfigurationManager.h"

// static
ConfigurationManager *ConfigurationManager::s_instance = NULL;

ConfigurationManager::ConfigurationManager()
{
}

ConfigurationManager::~ConfigurationManager()
{
}

ConfigurationManager * ConfigurationManager::getInstance()
{
	if (s_instance == NULL) {
		s_instance = new ConfigurationManager();
	}
	return s_instance;
}

bool ConfigurationManager::init(int argc, char * argv[])
{
	std::cout << "ConfigurationManager: initializing ..." << std::endl;

	if (argc < 7) {
		cerr << "Usage: DynWar --sampler <sampling strategy> --input <inputfile> --output <output file>" << endl;
		return false;
	}

	for (int i = 1; i < argc; ++i) {

		cout << i << ": " << argv[i] << " : ";

		if (std::string(argv[i]) == "--sampler") {
			config.samlingStrategy = argv[++i]; // Increment 'i' so we don't get the argument as the next argv[i].
			//cout << config.samlingStrategy << endl;
		}

		if (std::string(argv[i]) == "--input") {
			config.inputfile = argv[++i];
			//cout << config.inputfile << endl;
		}

		if (std::string(argv[i]) == "--output") {
			config.outputfile = argv[++i];
			//cout << config.outputfile << endl;
		}
	}

	cout << endl;

	return true;
}

string ConfigurationManager::getInput()
{
	return string(config.inputfile);
}

string ConfigurationManager::getOutput()
{
	return string(config.outputfile);
}

string ConfigurationManager::getSampler()
{
	return string(config.samlingStrategy);
}
