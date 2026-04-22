/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#05070b',
        foreground: '#e6edf6',
        card: '#0b1220',
        'card-foreground': '#e6edf6',
        primary: '#3b82f6',
        'primary-foreground': '#06101f',
        secondary: '#0f1b30',
        'secondary-foreground': '#e6edf6',
        muted: '#0d1729',
        'muted-foreground': '#93a4bd',
        accent: '#22c55e',
        'accent-foreground': '#06101f',
        destructive: '#ef4444',
        'destructive-foreground': '#06101f',
        border: '#17233a',
        input: '#111d33',
        ring: '#60a5fa',
      },
    },
  },
  plugins: [],
}
