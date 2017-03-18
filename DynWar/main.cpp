#include "main.h"

using namespace std;

int main(int argc, char** argv) {

	std::cout << "starting main..." << std::endl;

	//Get the main class initialized
	std::unique_ptr<DynWarden> dw_main(new DynWarden());
	

	std::cout << "main done." << std::endl;

	return 0;
}