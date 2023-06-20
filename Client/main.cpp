 #include <stdio.h>
#include <iostream>
#include "Client.h"

//std::string transferPath = "C:\\Users\\alper\\source\\repos\\mmn15_defensive_programming\\mmn15_defensive_programming\\transfer.info";
std::string transferPath = "transfer.info";
void fatalError(const char* str);

int main()
{
	std::cout << "Client started." << std::endl;
	Client c(transferPath);
	if (!c.parseTransferInfo())
	{
		fatalError("client failed handling transfer.info");
		return 1;
	}

	if (!c.start())
	{
		fatalError("client failed while running");
		return 1;
	}
	return 0;
}

void fatalError(const char* str)
{
	std::cout << "Fatal error: " << str << ". Shutting down immediately.\n";
	exit(1);
}