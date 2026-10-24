import { http, HttpResponse } from "msw"

/** `GET /api/v1/settings/site`: a country-level position, never a precise one. */
export const siteHandlers = [
  http.get("/api/v1/settings/site", () =>
    HttpResponse.json({ home: { lat: 46.8, lon: 8.2, label: "Switzerland" } }),
  ),
]
