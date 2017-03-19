#pragma once
#include "main.h"

using namespace std;

typedef struct {
	string inputfile;
	string outputfile;
	string samlingStrategy;
} configstruct_t;

class ConfigurationManager
{
public:
	ConfigurationManager();
	~ConfigurationManager();

	static ConfigurationManager *getInstance(); //get access to the one and only configuration manager instance

	bool init(int argc, char* argv[]);
	string getInput();
	string getOutput();
	string getSampler();


private:
	static ConfigurationManager *s_instance; //link to the globally available instance

	// structure to store the command line arguments and further configuration settings.
	configstruct_t config;
};

