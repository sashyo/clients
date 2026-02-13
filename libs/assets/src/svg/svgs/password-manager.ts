import { svg } from "../svg";

const PasswordManagerLogo = svg`
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 49" fill="none">
    <g class="tw-fill-fg-sidenav-text">
      <!-- TideWarden shield with wave cutout -->
      <path fill-rule="evenodd" d="M13 0.5 L25.5 3.5 V16.5 C25.5 22 20 27 13 30 C6 27 0.5 22 0.5 16.5 V3.5 Z M2.5 13.5 C5.5 10 9 10 13 13.5 C17 17 20.5 17 23.5 13.5 V17 C20.5 20.5 17 20.5 13 17 C9 13.5 5.5 13.5 2.5 17 Z"/>
      <!-- TideWarden text -->
      <text x="32" y="21" font-family="'Segoe UI', 'Helvetica Neue', Arial, sans-serif" font-size="16" font-weight="600" letter-spacing="-0.3">TideWarden</text>
      <!-- Password Manager subtitle -->
      <text x="32" y="43" font-family="'Segoe UI', 'Helvetica Neue', Arial, sans-serif" font-size="11" font-weight="400" opacity="0.7">Password Manager</text>
    </g>
  </svg>
`;

export default PasswordManagerLogo;
