import {
  AfterViewInit,
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  Input,
  OnChanges,
  OnDestroy,
  ViewChild,
} from "@angular/core";

@Component({
  selector: "app-react-host",
  template: `<div #reactContainer class="tw-w-full tw-h-full"></div>`,
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ReactHostComponent implements AfterViewInit, OnChanges, OnDestroy {
  @ViewChild("reactContainer", { static: true }) containerRef: ElementRef<HTMLDivElement>;
  @Input() component: any;
  @Input() props: Record<string, any> = {};

  private root: any;
  private queryClient: any;
  private themeInjected = false;

  ngAfterViewInit() {
    this.initReact();
  }

  ngOnChanges() {
    if (this.root) {
      this.renderReactComponent();
    }
  }

  ngOnDestroy() {
    if (this.root) {
      const root = this.root;
      const qc = this.queryClient;
      this.root = null;
      this.queryClient = null;
      setTimeout(() => {
        root.unmount();
        qc?.clear();
      }, 0);
    }
  }

  private initReact() {
    const ReactDOM = require("react-dom/client");
    const { QueryClient, injectThemeCSS } = require("@tideorg/ui");

    if (!this.themeInjected) {
      injectThemeCSS();
      this.themeInjected = true;
    }

    this.queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: 1,
          refetchOnWindowFocus: false,
        },
      },
    });

    this.root = ReactDOM.createRoot(this.containerRef.nativeElement);
    this.renderReactComponent();
  }

  private renderReactComponent() {
    if (!this.component || !this.root) {
      return;
    }

    const React = require("react");
    const { QueryClientProvider } = require("@tideorg/ui");

    const element = React.createElement(
      QueryClientProvider,
      { client: this.queryClient },
      React.createElement(this.component, this.props),
    );
    this.root.render(element);
  }
}
