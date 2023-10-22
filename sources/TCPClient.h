#pragma once
#include "netcommon.h"
#include <map>
#include "CMessage.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#if defined(_WIN64) || defined(_WIN32)
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#endif // defined(_WIN64) || defined(_WIN32)


#include "utils.h"

//#pragma warning(disable : 5208)

//==================================================================================================
class TCPClient{
public:
	TCPClient();
	TCPClient(const char*);
	~TCPClient();
	void start();
	void set_peer(const char* p) { _srv_name = p; };
    auto is_ready()->bool const {return _last_err_code==0;};
    auto send_to_server(IOMSG&) -> bool;
    auto get_server_msg(IOMSG&) -> bool;
    auto check_auth(const char* login, const char* pwd,std::string&)->bool;
    auto reg_user(const char* login, const char* pwd, std::string&)->bool;
    auto close_session()->void;


private:
#if defined(_WIN64) || defined(_WIN32)
	WSADATA _wsaData;
	SOCKET _socket{ INVALID_SOCKET };
#elif defined(__linux__)
	int _socket{-1};	
#endif
	
	int _last_err_code{ 0 };
	char _buffer[sizeof(IOMSG)]{'\0'};
	size_t _buf_len{ sizeof(IOMSG) };

	std::string _srv_name{"localhost"};
    auto _clean_up()->void;
    auto _init_connection() -> bool;
    auto _init_net_core()->bool;
	auto _unpack_available_users(const std::string&, std::map<size_t, std::string>&) -> void;
    auto _send_to_server(IOMSG&) -> bool;
    auto _is_valid_socket()->bool;
	uint64_t _usr_db_id{};

};

using TCPC = TCPClient;

