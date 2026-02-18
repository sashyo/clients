import { css } from "@emotion/css";
import { html } from "lit";

import { IconProps } from "../common-types";
import { buildIconColorRule, ruleNames, themes } from "../constants/styles";

export function Shield({ ariaHidden = true, color, theme }: IconProps) {
  const shapeColor = color || themes[theme].brandLogo;

  return html`
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 38 44"
      fill="none"
      aria-hidden="${ariaHidden}"
    >
      <path
        class=${css(buildIconColorRule(shapeColor, ruleNames.fill))}
        fill-rule="evenodd"
        d="M19 1L37 5V24C37 32 29 39 19 43C9 39 1 32 1 24V5L19 1ZM4 19.5C8 14.5 13 14.5 19 19.5C25 24.5 30 24.5 34 19.5V24.5C30 29.5 25 29.5 19 24.5C13 19.5 8 19.5 4 24.5V19.5Z"
      />
    </svg>
  `;
}
