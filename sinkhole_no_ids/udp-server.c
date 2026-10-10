#include "contiki.h"

#include "net/routing/routing.h"
#include "net/ipv6/simple-udp.h"

#include "sys/log.h"

#define LOG_MODULE "No-IDS-Root"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

static struct simple_udp_connection udp_conn;

PROCESS(udp_server_process, "Sinkhole No-IDS root");
AUTOSTART_PROCESSES(&udp_server_process);

/*---------------------------------------------------------------------------*/

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  if(datalen > 0) {

    LOG_INFO("Received packet from ");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_("\n");

    /*
     * Normal application traffic is still accepted and echoed.
     */
    if(data[0] == 'N') {
      simple_udp_sendto(&udp_conn,
                        data,
                        datalen,
                        sender_addr);
    }
  }
}

/*---------------------------------------------------------------------------*/

PROCESS_THREAD(udp_server_process, ev, data)
{
  PROCESS_BEGIN();

  /*
   * Start this node as the RPL border router/root.
   * No IDS monitoring or mitigation is performed.
   */
  NETSTACK_ROUTING.root_start();

  simple_udp_register(&udp_conn,
                      UDP_SERVER_PORT,
                      NULL,
                      UDP_CLIENT_PORT,
                      udp_rx_callback);

  LOG_INFO("Secure IoT Sinkhole No-IDS root starting\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
