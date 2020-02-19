#include <stdbool.h>
#include <arpa/inet.h>

#include "../handle_packet.h"
#include "../globals.h"


#include <stdlib.h>
#define ASSERT_EQ(num, expr)  if (num != expr) { printf("Assert failed: " #num " != " #expr "\nIn %s:%d %s()\n", __FILE__, __LINE__, __func__); exit(1); }

int main(int argc, char* argv[]) {
	struct in6_addr addr;

	inet_pton(AF_INET6, "::ffff:151.12.34.1", &addr);
	ASSERT_EQ(false, check_local(&addr));

	inet_pton(AF_INET6, "::ffff:10.0.0.0", &addr);
	ASSERT_EQ(true, check_local(&addr));
	
	inet_pton(AF_INET6, "ff02::1:ff91:cf6b", &addr);
	ASSERT_EQ(true, check_local(&addr));

	inet_pton(AF_INET6, "ff02::1:ff00:1", &addr);
	ASSERT_EQ(true, check_local(&addr));

}
