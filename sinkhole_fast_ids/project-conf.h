#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/*
 * Enable the RPL sinkhole DIO advertisement modification.
 */
#define RPL_SINKHOLE_ATTACK 1

/*
 * Advertise a rank only slightly above ROOT_RANK.
 * This is valid enough to be accepted by RPL-Lite but
 * artificially attractive compared with a normal child rank.
 */
#define RPL_SINKHOLE_ADVERTISED_RANK (ROOT_RANK + 32)

#endif /* PROJECT_CONF_H_ */
