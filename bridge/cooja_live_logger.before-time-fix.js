(function() {

  var LOG_PATH = "/home/yash/secure-iot-ids/live_cooja_ids.log";
  var writer = null;

  function timestamp(ms) {
    var totalSeconds = Math.floor(Number(ms) / 1000);
    var minutes = Math.floor(totalSeconds / 60);
    var seconds = totalSeconds % 60;
    var millis = Number(ms) % 1000;

    function pad(v, n) {
      var s = String(v);
      while (s.length < n) s = "0" + s;
      return s;
    }

    return pad(minutes, 2) + ":" +
           pad(seconds, 2) + "." +
           pad(millis, 3);
  }

  try {
    writer = new java.io.FileWriter(LOG_PATH, true);

    writer.write("00:00.000 ID:0 SCRIPT_LOGGER_STARTED\n");
    writer.flush();

    log.log("FILE LOGGER STARTED\n");

    while (true) {
      YIELD();

      var line =
        timestamp(time) +
        " ID:" + id + " " + msg + "\n";

      writer.write(line);
      writer.flush();

      log.log("FILE LOGGER: " + line);
    }

  } catch (e) {
    log.log("FILE LOGGER ERROR: " + e + "\n");
  } finally {
    if (writer != null) {
      writer.close();
    }
  }

})();