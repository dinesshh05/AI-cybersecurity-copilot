import type { Config } from "tailwindcss"

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#08111f",
        panel: "#0d1a2d",
        panel2: "#10213a",
        accent: "#50e3c2",
        warning: "#f5a524",
        danger: "#ff5c7a",
        text: "#eaf2ff",
        muted: "#9fb3cc",
      },
      boxShadow: {
        neon: "0 0 0 1px rgba(80, 227, 194, 0.18), 0 24px 70px rgba(0, 0, 0, 0.35)",
      },
    },
  },
  plugins: [],
}

export default config

