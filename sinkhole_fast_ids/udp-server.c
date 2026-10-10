#include "contiki.h"

#include "net/routing/routing.h"
#include "net/routing/rpl-lite/rpl.h"
#include "net/routing/rpl-lite/rpl-dag.h"
#include "net/routing/rpl-lite/rpl-neighbor.h"

#include "net/nbr-table.h"
#include "net/ipv6/simple-udp.h"

#include "sys/log.h"

#define LOG_MODULE "IDS-Sinkhole"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

/*
 * A normal child should have a rank at least one full
 * MinHopRankInc above the root.
 *
 * A rank below ROOT_RANK + half the minimum hop increment
 * is considered suspicious for this experiment.
 */
#define SINKHOLE_RANK_THRESHOLD \
  (ROOT_RANK + (RPL_MIN_HOPRANKINC / 2))

#define IDS_SCAN_INTERVAL (1 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;

static bool sinkhole_detected = false;
static bool mitigation_started = false;

PROCESS(udp_server_process, "Sinkhole IDS server");
AUTOSTART_PROCESSES(&udp_server_process);

/*---------------------------------------------------------------------------*/

static void
send_block(rpl_nbr_t *nbr)
{
  uip_ipaddr_t *addr = rpl_neighbor_get_ipaddr(nbr);

  if(addr != NULL) {

    const char block_msg[] = "BLOCK";

    simple_udp_sendto(&udp_conn,
                      block_msg,
                      sizeof(block_msg) - 1,
                      addr);

    LOG_WARN("IDS ACTION: BLOCK sent to sinkhole ");
    LOG_WARN_6ADDR(addr);
    LOG_WARN_("\n");
  }
}

/*---------------------------------------------------------------------------*/

static void
check_rpl_neighbors(void)
{
  rpl_nbr_t *nbr;

  if(sinkhole_detected) {
    return;
  }

  nbr = (rpl_nbr_t *)nbr_table_head(rpl_neighbors);

  while(nbr != NULL) {

    if(nbr->rank < SINKHOLE_RANK_THRESHOLD) {

      uip_ipaddr_t *addr = rpl_neighbor_get_ipaddr(nbr);

      if(addr != NULL) {

        LOG_WARN("IDS ALERT: SINKHOLE DETECTED node=");
        LOG_WARN_6ADDR(addr);
        LOG_WARN_(" advertised_rank=%u threshold=%u\n",
                  (unsigned)nbr->rank,
                  (unsigned)SINKHOLE_RANK_THRESHOLD);

        sinkhole_detected = true;

        /*
         * Send BLOCK before global repair so the malicious
         * node can receive the mitigation command.
         */
        send_block(nbr);

        LOG_WARN("IDS ACTION: sinkhole node isolated\n");

        /*
         * Start a new RPL DAG version and force the network
         * to rebuild routing information.
         */
        rpl_global_repair("Sinkhole mitigation");

        LOG_WARN("IDS ACTION: RPL global repair triggered\n");

        mitigation_started = true;

        return;
      }
    }

    nbr = (rpl_nbr_t *)nbr_table_next(rpl_neighbors,
                                      (nbr_table_item_t *)nbr);
  }
}

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
  /*
   * Normal application traffic is still accepted.
   */
  if(datalen > 0) {

    LOG_INFO("Received packet from ");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_("\n");

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
  static struct etimer scan_timer;

  PROCESS_BEGIN();

  NETSTACK_ROUTING.root_start();

  simple_udp_register(&udp_conn,
                      UDP_SERVER_PORT,
                      NULL,
                      UDP_CLIENT_PORT,
                      udp_rx_callback);

  LOG_INFO("Secure IoT Sinkhole IDS server starting\n");

  etimer_set(&scan_timer, IDS_SCAN_INTERVAL);

  while(1) {

    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&scan_timer));

    check_rpl_neighbors();

    etimer_reset(&scan_timer);
  }

  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
