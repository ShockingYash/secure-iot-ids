#include "contiki.h"
#include "net/routing/routing.h"
#include "net/routing/rpl-lite/rpl.h"
#include "net/routing/rpl-lite/rpl-dag.h"
#include "net/routing/rpl-lite/rpl-neighbor.h"
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

#define SEND_INTERVAL (60 * CLOCK_SECOND)
#define FIRST_SEND_DELAY (5 * CLOCK_SECOND)
#define PARENT_LOG_INTERVAL (2 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;

static uint32_t tx_count;
static uint32_t rx_count;
static uint32_t missed_tx_count;

/*---------------------------------------------------------------------------*/

static void
log_rpl_parent(void)
{
  rpl_dag_t *dag = rpl_get_any_dag();

  if(dag == NULL) {
    LOG_INFO("RPL PARENT: no DAG\n");
    return;
  }

  if(dag->preferred_parent == NULL) {
    LOG_INFO("RPL PARENT: none local_rank=%u\n",
             (unsigned)dag->rank);
    return;
  }

  {
    uip_ipaddr_t *parent_addr =
      rpl_neighbor_get_ipaddr(dag->preferred_parent);

    if(parent_addr != NULL) {
      LOG_INFO("RPL PARENT: ");
      LOG_INFO_6ADDR(parent_addr);
      LOG_INFO_(" rank=%u local_rank=%u\n",
                (unsigned)dag->preferred_parent->rank,
                (unsigned)dag->rank);
    } else {
      LOG_INFO("RPL PARENT: selected but address unavailable local_rank=%u\n",
               (unsigned)dag->rank);
    }
  }
}

/*---------------------------------------------------------------------------*/

PROCESS(normal_node_process, "Normal IoT node");
PROCESS(rpl_parent_monitor_process, "RPL parent monitor");

AUTOSTART_PROCESSES(&normal_node_process,
                    &rpl_parent_monitor_process);

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
             datalen, (char *)data);
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

  etimer_set(&periodic_timer,
             FIRST_SEND_DELAY +
             (random_rand() % FIRST_SEND_DELAY));

  while(1) {

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if(NETSTACK_ROUTING.node_is_reachable() &&
       NETSTACK_ROUTING.get_root_ipaddr(&root_ipaddr)) {

      snprintf(message,
               sizeof(message),
               "N,%lu,%lu",
               (unsigned long)tx_count,
               (unsigned long)clock_time());

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

    etimer_set(&periodic_timer,
               SEND_INTERVAL
               - CLOCK_SECOND
               + (random_rand() % (2 * CLOCK_SECOND)));
  }

  PROCESS_END();
}

/*---------------------------------------------------------------------------*/

PROCESS_THREAD(rpl_parent_monitor_process, ev, data)
{
  static struct etimer parent_timer;

  PROCESS_BEGIN();

  etimer_set(&parent_timer, 2 * CLOCK_SECOND);

  while(1) {

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&parent_timer));

    log_rpl_parent();

    etimer_reset(&parent_timer);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
