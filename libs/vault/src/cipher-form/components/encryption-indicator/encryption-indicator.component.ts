import { CommonModule } from "@angular/common";
import { ChangeDetectionStrategy, Component, input } from "@angular/core";

import { JslibModule } from "@bitwarden/angular/jslib.module";
import { TooltipDirective } from "@bitwarden/components";

@Component({
  selector: "vault-encryption-indicator",
  standalone: true,
  imports: [CommonModule, JslibModule, TooltipDirective],
  template: `
    <i
      class="bwi bwi-sm"
      [ngClass]="encrypted() ? 'bwi-lock' : 'bwi-unlock'"
      [bitTooltip]="(encrypted() ? 'fieldEncrypted' : 'fieldNotEncrypted') | i18n"
      aria-hidden="true"
    ></i>
  `,
  host: {
    "[attr.slot]": "'end'",
    class: "tw-inline-flex tw-items-center",
  },
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EncryptionIndicatorComponent {
  readonly encrypted = input.required<boolean>();
}
