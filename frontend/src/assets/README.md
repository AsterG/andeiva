# Static map geometry

`world-map.svg` is derived from Natural Earth's 1:110m countries dataset,
which is in the public domain. The equirectangular projection omits Antarctica.
It contains no network observations, locations of users, or traffic flows.

- Source: https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_admin_0_countries.geojson
- Terms: https://www.naturalearthdata.com/about/terms-of-use/
- Source dataset SHA-256: `6866c877d39cba9c357620878839b336d569f8c662d3cfab4cb1dbe2d39c977f`

The dashboard displays the geometry only as a static background when geographic
traffic telemetry is unavailable. It must not imply geolocation support.
