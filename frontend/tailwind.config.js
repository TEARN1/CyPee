/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0b0f19",
          panel: "#151b2c",
          border: "#252f48",
          text: "#f8fafc",
          muted: "#8a9cbd",
          accent: "#6366f1",
          accent2: "#a855f7",
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#3b82f6",
        }
      }
    },
  },
  plugins: [],
}
