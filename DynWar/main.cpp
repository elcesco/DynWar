#include "main.h"

#include "ConfigurationManager.h"
#include "DynWarden.h"

int main(int argc, char** argv) {

    // Reading the command line arguments and ensure they are complete and valid
    std::unique_ptr<ConfigurationManager> _config(ConfigurationManager::getInstance());
    if (_config->init(argc, argv)) {

        // *********************************************************************
        // declare ourselves as highest priority process and switch off any 
        // disturbance.
        // *********************************************************************
        
        // TODO
        
        // *********************************************************************
        //Get the main class initialized
        // *********************************************************************
        std::unique_ptr<DynWarden> _warden(DynWarden::getInstance());


        // *********************************************************************
        // get the experiment started
        // *********************************************************************
        _warden->start();

    } else {
        cerr << "main: Failed to parse commandline arguments." << endl;
        return 1;
    }

    return 0;
}