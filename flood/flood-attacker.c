#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sys/log.h"

#define LOG_MODULE "FloodAttack"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

/* 10 packets/second */
#define FLOOD_INTERVAL (CLOCK_SECOND / 10)

#define START_DELAY (5 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;

static uint8_t blocked = 0;
static uint32_t flood_count = 0;

/*---------------------------------------------------------------------------*/
PROCESS(flood_attacker_process, "Flooding attacker");
AUTOSTART_PROCESSES(&flood_attacker_process);
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
  if(datalen >= 5 && memcmp(data, "BLOCK", 5) == 0) {
    blocked = 1;

    LOG_INFO("MITIGATION: BLOCK received from IDS\n");
    LOG_INFO("MITIGATION: attacker stopped\n");
  }
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(flood_attacker_process, ev, data)
{
  static struct etimer flood_timer;
  static char message[32];

  uip_ipaddr_t root_ipaddr;

  PROCESS_BEGIN();

  LOG_INFO("Flooding attacker starting\n");

  simple_udp_register(&udp_conn,
                      UDP_CLIENT_PORT,
                      NULL,
                      UDP_SERVER_PORT,
                      udp_rx_callback);

  etimer_set(&flood_timer, START_DELAY);

  while(1) {

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&flood_timer));

    if(!blocked &&
       NETSTACK_ROUTING.node_is_reachable() &&
       NETSTACK_ROUTING.get_root_ipaddr(&root_ipaddr)) {

      snprintf(message,
               sizeof(message),
               "F,%lu",
               (unsigned long)flood_count);

      simple_udp_sendto(&udp_conn,
                        message,
                        strlen(message),
                        &root_ipaddr);

      flood_count++;

      LOG_INFO("FLOOD TX seq=%lu\n",
               (unsigned long)flood_count);
    }

    etimer_set(&flood_timer, FLOOD_INTERVAL);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
