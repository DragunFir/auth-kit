import { createTheme } from "@mui/material/styles";

export const appTheme = createTheme({
  palette: {
    mode: "light",
    primary: {
      main: "#0f766e",
      dark: "#115e59",
      light: "#5eead4",
    },
    secondary: {
      main: "#c2410c",
      dark: "#9a3412",
      light: "#fdba74",
    },
    background: {
      default: "#f5efe4",
      paper: "rgba(255, 250, 241, 0.86)",
    },
    text: {
      primary: "#172554",
      secondary: "#334155",
    },
  },
  shape: {
    borderRadius: 18,
  },
  typography: {
    fontFamily: '"IBM Plex Sans", "Avenir Next", "Segoe UI", sans-serif',
    h1: {
      fontFamily: '"Avenir Next Condensed", "IBM Plex Sans Condensed", sans-serif',
      fontWeight: 700,
      letterSpacing: "-0.04em",
    },
    h2: {
      fontFamily: '"Avenir Next Condensed", "IBM Plex Sans Condensed", sans-serif',
      fontWeight: 700,
      letterSpacing: "-0.03em",
    },
    h3: {
      fontFamily: '"Avenir Next Condensed", "IBM Plex Sans Condensed", sans-serif',
      fontWeight: 700,
    },
    button: {
      textTransform: "none",
      fontWeight: 700,
    },
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          backdropFilter: "blur(18px)",
          border: "1px solid rgba(15, 118, 110, 0.12)",
          boxShadow: "0 18px 60px rgba(23, 37, 84, 0.10)",
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 999,
          paddingInline: 18,
        },
      },
    },
    MuiTextField: {
      defaultProps: {
        fullWidth: true,
        size: "small",
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: 999,
        },
      },
    },
  },
});
