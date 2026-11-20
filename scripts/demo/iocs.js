/**
 * Indicators and attacker sources shared by the Wazuh alerts and the OpenCTI dataset, so a demo investigation really finds a
 * match. All addresses are from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), domains use reserved
 * TLDs, and hashes are random: nothing here points at a real system.
 */
const IOC = {
  c2Ip: "203.0.113.45",
  c2Ip2: "192.0.2.141",
  exfilIp: "192.0.2.150",
  sprayIp: "203.0.113.9",
  webAttackIp: "198.51.100.17",
  log4jIp: "198.51.100.18",
  phishDomain: "secure-m365-login.example",
  c2Domain: "update-check.example",
  dgaDomain: "xk3jq9vbt2.example",
  payloadUrl: "http://203.0.113.45/payload.bin",
  phishUrl: "https://secure-m365-login.example/auth/verify?session=7f3a",
  dropperSha256: "9f2c4b7a1d8e03f5a6c9b2d41e7f08a35c6d9e1b2a4f70c83d5e6b1a9c2f7e41",
  ransomSha256: "3b8e5d1a7c40f92e6b3d8a1c5f7e29b04d6a8c3e1f5b7092d4a6c8e0b2f4a613",
  webshellSha256: "c41d7e0a92b58f3d6e1a4c7b0d93f25a8e6c1b4d7f02a95c3e8b6d1f4a7c0e29",
  mimikatzSha256: "e6a1f3d8b05c7294a1e8d3f6b0c52a97d4e1f8b3a6c05d92e7f4a1b8c3d60e5f"
};

/**
 * Geolocated attacker sources: [ip, lat, lon, city, country, profile, weight]. The profile decides which attacks come from the
 * address; the weight is its share of that profile's alerts. Coordinates are those of the named city, not an attribution.
 */
const SOURCES = [
  [IOC.c2Ip, 55.75, 37.62, "Moscow", "Russia", "c2", 9],
  ["203.0.113.46", 59.93, 30.34, "Saint Petersburg", "Russia", "ssh", 5],
  [IOC.webAttackIp, 39.9, 116.4, "Beijing", "China", "web", 8],
  [IOC.log4jIp, 31.23, 121.47, "Shanghai", "China", "ssh", 6],
  ["198.51.100.19", 22.54, 114.06, "Shenzhen", "China", "scan", 4],
  ["198.51.100.20", 22.32, 114.17, "Hong Kong", "Hong Kong", "c2", 3],
  ["192.0.2.88", 50.11, 8.68, "Frankfurt", "Germany", "web", 5],
  ["192.0.2.89", 52.37, 4.9, "Amsterdam", "Netherlands", "c2", 4],
  ["192.0.2.90", 48.86, 2.35, "Paris", "France", "scan", 2],
  ["192.0.2.91", 51.51, -0.13, "London", "United Kingdom", "phish", 2],
  ["192.0.2.92", 50.45, 30.52, "Kyiv", "Ukraine", "ssh", 3],
  ["192.0.2.93", 44.43, 26.1, "Bucharest", "Romania", "web", 3],
  ["192.0.2.94", 35.69, 51.39, "Tehran", "Iran", "ssh", 4],
  ["192.0.2.95", 41.01, 28.98, "Istanbul", "Turkey", "phish", 3],
  ["203.0.113.200", -23.55, -46.63, "Sao Paulo", "Brazil", "ssh", 4],
  ["203.0.113.201", -34.6, -58.38, "Buenos Aires", "Argentina", "scan", 2],
  ["203.0.113.202", 19.43, -99.13, "Mexico City", "Mexico", "web", 2],
  ["203.0.113.203", 4.71, -74.07, "Bogota", "Colombia", "ssh", 2],
  ["192.0.2.140", 37.77, -122.42, "San Francisco", "United States", "scan", 3],
  [IOC.c2Ip2, 39.04, -77.49, "Ashburn", "United States", "c2", 5],
  ["192.0.2.142", 32.78, -96.8, "Dallas", "United States", "web", 3],
  ["192.0.2.143", 41.88, -87.63, "Chicago", "United States", "phish", 2],
  ["192.0.2.144", 43.65, -79.38, "Toronto", "Canada", "scan", 2],
  [IOC.sprayIp, 6.52, 3.38, "Lagos", "Nigeria", "spray", 4],
  ["203.0.113.10", -26.2, 28.05, "Johannesburg", "South Africa", "ssh", 2],
  ["203.0.113.11", 30.04, 31.24, "Cairo", "Egypt", "scan", 2],
  ["203.0.113.12", -1.29, 36.82, "Nairobi", "Kenya", "web", 1],
  ["198.51.100.99", 1.35, 103.82, "Singapore", "Singapore", "c2", 4],
  ["198.51.100.100", 37.57, 126.98, "Seoul", "South Korea", "ssh", 3],
  ["198.51.100.101", 35.68, 139.69, "Tokyo", "Japan", "scan", 2],
  ["198.51.100.102", 25.03, 121.57, "Taipei", "Taiwan", "web", 2],
  ["198.51.100.103", 21.03, 105.85, "Hanoi", "Vietnam", "ssh", 3],
  ["198.51.100.104", -6.21, 106.85, "Jakarta", "Indonesia", "spray", 2],
  ["198.51.100.105", 24.86, 67.01, "Karachi", "Pakistan", "phish", 2],
  ["198.51.100.106", 23.81, 90.41, "Dhaka", "Bangladesh", "ssh", 2],
  ["198.51.100.107", -33.87, 151.21, "Sydney", "Australia", "scan", 1],
  ["198.51.100.108", 25.2, 55.27, "Dubai", "United Arab Emirates", "spray", 2],
  ["198.51.100.109", 24.71, 46.68, "Riyadh", "Saudi Arabia", "web", 1],
  [IOC.exfilIp, 53.9, 27.57, "Minsk", "Belarus", "c2", 3],
  ["192.0.2.151", 52.23, 21.01, "Warsaw", "Poland", "web", 2],
  ["192.0.2.152", 59.33, 18.07, "Stockholm", "Sweden", "scan", 1],
  ["192.0.2.153", 40.42, -3.7, "Madrid", "Spain", "ssh", 1],
  ["192.0.2.154", -12.05, -77.04, "Lima", "Peru", "ssh", 1],
  ["192.0.2.155", -33.45, -70.67, "Santiago", "Chile", "scan", 1]
].map(([ip, lat, lon, city, country, profile, weight]) => ({ ip, lat, lon, city, country, profile, weight }));

module.exports = { IOC, SOURCES };
