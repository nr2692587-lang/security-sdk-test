// Safe example configuration
// This file intentionally contains benign example content only.

function getExampleConfig() {
  return {
    environment: 'development',
    featureFlags: {
      demoMode: true,
      logging: true,
    },
  };
}

function formatExampleMessage(name) {
  return `Hello, ${name}!`;
}

module.exports = {
  getExampleConfig,
  formatExampleMessage,
};
