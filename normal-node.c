#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sys/log.h"

#define LOG_MODULE "NormalNode"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

/* Project target: approximately one packet per 60 seconds */
#define SEND_INTERVAL (60 * CLOCK_SECOND)

/* Short initial delay so the first packet appears during testing */
#define FIRST_SEND_DELAY (5 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;

static uint32_t tx_count = 0;
static uint32_t rx_count = 0;
static uint32_t missed_tx_count = 0;
static uint32_t last_send_tick = 0;

/*---------------------------------------------------------------------------*/
PROCESS(normal_node_process, "Normal IoT node");
AUTOSTART_PROCESSES(&normal_node_process);
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
  unsigned long sequence;
  unsigned long sent_tick;

  rx_count++;

  /*
   * Payload format:
   * N,<sequence>,<send_clock_tick>
   */
  if(sscanf((const char *)data, "N,%lu,%lu",
            &sequence, &sent_tick) == 2) {

    uint32_t latency_ticks = clock_time() - (uint32_t)sent_tick;
    uint32_t latency_ms =
      (latency_ticks * 1000UL) / CLOCK_SECOND;

    LOG_INFO("RESPONSE seq=%lu latency_ms=%lu\n",
             sequence,
             (unsigned long)latency_ms);
  } else {
    LOG_INFO("RESPONSE payload=%.*s\n",
             datalen,
             (char *)data);
  }

  LOG_INFO("NORMAL METRIC tx=%lu rx=%lu missed=%lu\n",
           (unsigned long)tx_count,
           (unsigned long)rx_count,
           (unsigned long)missed_tx_count);
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(normal_node_process, ev, data)
{
  static struct etimer periodic_timer;
  static char message[48];

  uip_ipaddr_t root_ipaddr;

  PROCESS_BEGIN();

  LOG_INFO("Normal IoT node starting\n");

  simple_udp_register(&udp_conn,
                      UDP_CLIENT_PORT,
                      NULL,
                      UDP_SERVER_PORT,
                      udp_rx_callback);

  /*
   * Initial delay: approximately 5 seconds.
   */
  etimer_set(&periodic_timer,
             FIRST_SEND_DELAY +
             (random_rand() % FIRST_SEND_DELAY));

  while(1) {

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if(NETSTACK_ROUTING.node_is_reachable() &&
       NETSTACK_ROUTING.get_root_ipaddr(&root_ipaddr)) {

      last_send_tick = clock_time();

      snprintf(message,
               sizeof(message),
               "N,%lu,%lu",
               (unsigned long)tx_count,
               (unsigned long)last_send_tick);

      LOG_INFO("NORMAL TX seq=%lu -> ",
               (unsigned long)tx_count);
      LOG_INFO_6ADDR(&root_ipaddr);
      LOG_INFO_("\n");

      simple_udp_sendto(&udp_conn,
                        message,
                        strlen(message),
                        &root_ipaddr);

      tx_count++;

    } else {

      LOG_INFO("RPL root not reachable yet\n");

      if(tx_count > 0) {
        missed_tx_count++;
      }
    }

    /*
     * Approximately 59-61 seconds between normal transmissions.
     */
    etimer_set(&periodic_timer,
               SEND_INTERVAL
               - CLOCK_SECOND
               + (random_rand() % (2 * CLOCK_SECOND)));
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
