#include "contiki.h"
#include "net/routing/routing.h"
#include "net/ipv6/simple-udp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sys/log.h"

#define LOG_MODULE "IDS-Server"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

/* Project design target */
#define FLOOD_THRESHOLD 5

/* Maximum number of source addresses tracked by the IDS */
#define MAX_TRACKED_SOURCES 16

typedef struct {
  uint8_t used;
  uint8_t blacklisted;
  uip_ipaddr_t addr;
  uint16_t packet_count;
  uint32_t window_second;
} source_stat_t;

static source_stat_t sources[MAX_TRACKED_SOURCES];
static struct simple_udp_connection udp_conn;

static uint32_t total_received = 0;
static uint32_t normal_received = 0;
static uint32_t attack_detected = 0;

/*---------------------------------------------------------------------------*/
PROCESS(udp_server_process, "Secure IoT IDS UDP server");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/

static source_stat_t *
find_source(const uip_ipaddr_t *addr)
{
  int i;

  for(i = 0; i < MAX_TRACKED_SOURCES; i++) {
    if(sources[i].used && uip_ipaddr_cmp(&sources[i].addr, addr)) {
      return &sources[i];
    }
  }

  for(i = 0; i < MAX_TRACKED_SOURCES; i++) {
    if(!sources[i].used) {
      sources[i].used = 1;
      sources[i].blacklisted = 0;
      uip_ipaddr_copy(&sources[i].addr, addr);
      sources[i].packet_count = 0;
      sources[i].window_second = clock_seconds();
      return &sources[i];
    }
  }

  return NULL;
}

/*---------------------------------------------------------------------------*/
static void
blacklist_source(source_stat_t *source)
{
  if(source == NULL || source->blacklisted) {
    return;
  }

  source->blacklisted = 1;
  attack_detected++;

  LOG_INFO("IDS ALERT: FLOODING DETECTED source=");
  LOG_INFO_6ADDR(&source->addr);
  LOG_INFO_(" rate=%u packets/sec\n", source->packet_count);

  /*
   * Send a BLOCK command to the attacker.
   * The attacker firmware will stop transmitting after receiving it.
   */
  {
    const char block_message[] = "BLOCK";

    simple_udp_sendto(&udp_conn,
                      block_message,
                      strlen(block_message),
                      &source->addr);
  }

  LOG_INFO("IDS ACTION: source blacklisted and BLOCK sent\n");
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
  source_stat_t *source;
  uint32_t now_second;

  total_received++;

  source = find_source(sender_addr);

  if(source == NULL) {
    LOG_WARN("IDS source table full, packet dropped\n");
    return;
  }

  if(source->blacklisted) {
    LOG_INFO("IDS DROP: blacklisted source=");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_("\n");
    return;
  }

  now_second = clock_seconds();

  if(now_second != source->window_second) {
    source->window_second = now_second;
    source->packet_count = 0;
  }

  source->packet_count++;

  /*
   * Flooding detection:
   * more than 5 packets in one second from the same source.
   */
  if(source->packet_count > FLOOD_THRESHOLD) {
    blacklist_source(source);

    LOG_INFO("IDS DROP: flooding packet from source=");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_("\n");
    return;
  }

  /*
   * Normal application traffic uses the N prefix.
   */
  if(datalen > 0 && data[0] == 'N') {
    normal_received++;

    LOG_INFO("NORMAL RX from ");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_(" payload=%.*s\n", datalen, (char *)data);

    /* Echo the normal application packet */
    simple_udp_sendto(&udp_conn,
                      data,
                      datalen,
                      sender_addr);
  } else if(datalen > 0 && data[0] == 'F') {
    /*
     * The packet is from a flooding attacker.
     * We deliberately do not echo it.
     */
    LOG_INFO("ATTACK RX from ");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_("\n");
  } else {
    LOG_INFO("UNKNOWN RX from ");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_("\n");
  }

  LOG_INFO("IDS METRIC total_rx=%lu normal_rx=%lu "
           "attacks_detected=%lu\n",
           (unsigned long)total_received,
           (unsigned long)normal_received,
           (unsigned long)attack_detected);
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("Secure IoT IDS server starting\n");

  /* Make this node the RPL DAG root */
  NETSTACK_ROUTING.root_start();

  /* Register UDP server */
  simple_udp_register(&udp_conn,
                      UDP_SERVER_PORT,
                      NULL,
                      UDP_CLIENT_PORT,
                      udp_rx_callback);

  LOG_INFO("RPL root and UDP IDS server ready\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
