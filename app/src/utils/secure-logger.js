const { sanitizeLogData } = require("./log-sanitizer");

function writeLog(level, message, metadata) {
  const record = sanitizeLogData({
    timestamp: new Date().toISOString(),
    level,
    message,
    ...(metadata === undefined ? {} : { metadata }),
  });

  const output = JSON.stringify(record);

  if (level === "error") {
    console.error(output);
    return;
  }

  if (level === "warn") {
    console.warn(output);
    return;
  }

  console.log(output);
}

const logger = {
  info(message, metadata) {
    writeLog("info", message, metadata);
  },

  warn(message, metadata) {
    writeLog("warn", message, metadata);
  },

  error(message, metadata) {
    writeLog("error", message, metadata);
  },
};

module.exports = logger;
