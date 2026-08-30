import "./styles.css";

const DEFAULT_RELEASE_URL = "https://github.com/0xmdrakib/OmniRelay/releases/latest";
const configuredReleaseUrl = import.meta.env.VITE_RELEASE_URL?.trim();
const releaseUrl = configuredReleaseUrl || DEFAULT_RELEASE_URL;

document.querySelectorAll<HTMLAnchorElement>("[data-release-link]").forEach((link) => {
  link.href = releaseUrl;
  link.title = "Open the official OmniRelay release page";
});

const menuButton = document.querySelector<HTMLButtonElement>(".menu-button");
const navigation = document.querySelector<HTMLElement>("#site-nav");

const setMenuOpen = (open: boolean) => {
  if (!menuButton || !navigation) return;
  menuButton.setAttribute("aria-expanded", String(open));
  navigation.classList.toggle("is-open", open);
  document.body.classList.toggle("menu-open", open);
};

menuButton?.addEventListener("click", () => {
  setMenuOpen(menuButton.getAttribute("aria-expanded") !== "true");
});

navigation?.querySelectorAll("a").forEach((link) => {
  link.addEventListener("click", () => setMenuOpen(false));
});

window.addEventListener("keydown", (event) => {
  if (event.key === "Escape") setMenuOpen(false);
});

window.addEventListener("resize", () => {
  if (window.innerWidth >= 768) setMenuOpen(false);
});
