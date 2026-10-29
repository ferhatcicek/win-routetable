# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import json
import threading
import time
import re


class RouteVisualizer:
    def __init__(self, root):
        self.root = root

        self.root.title("Windows 11 - Routing Table Görselleştirici")
        self.root.geometry("1500x900")
        self.root.minsize(1100, 700)

        # -----------------------------------------------------
        # STATE
        # -----------------------------------------------------

        self.routes = []

        self.auto_refresh = tk.BooleanVar(value=True)
        self.ip_version = tk.StringVar(value="IPv4")
        self.refresh_seconds = tk.IntVar(value=5)

        self.refresh_job = None
        self.refresh_running = False
        self.closed = False

        self.zoom = 1.0
        self.offset_x = 0
        self.offset_y = 0

        self.drag_start = None

        self.selected_route = None

        # -----------------------------------------------------
        # COLORS
        # -----------------------------------------------------

        self.bg = "#f5f7fa"
        self.panel = "#ffffff"
        self.border = "#d5d9df"

        self.interface_color = "#dbeafe"
        self.interface_border = "#3b82f6"

        self.gateway_color = "#dcfce7"
        self.gateway_border = "#22c55e"

        self.destination_color = "#fef3c7"
        self.destination_border = "#f59e0b"

        self.default_color = "#fee2e2"
        self.default_border = "#ef4444"

        self.text_color = "#172033"
        self.secondary_text = "#667085"
        self.line_color = "#98a2b3"

        # -----------------------------------------------------
        # UI
        # -----------------------------------------------------

        self.create_style()
        self.create_ui()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )

        self.refresh_routes()

    # =========================================================
    # STYLE
    # =========================================================

    def create_style(self):

        style = ttk.Style()

        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            font=("Segoe UI", 9),
            rowheight=28,
            background="white",
            fieldbackground="white"
        )

        style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 9, "bold")
        )

        style.configure(
            "TButton",
            font=("Segoe UI", 9)
        )

        style.configure(
            "TLabel",
            font=("Segoe UI", 9)
        )

    # =========================================================
    # UI
    # =========================================================

    def create_ui(self):

        # -----------------------------------------------------
        # HEADER
        # -----------------------------------------------------

        header = ttk.Frame(
            self.root,
            padding=(12, 10)
        )
        header.pack(
            fill=tk.X
        )

        ttk.Label(
            header,
            text="Windows 11 Routing Table",
            font=("Segoe UI", 15, "bold")
        ).pack(
            side=tk.LEFT
        )

        ttk.Label(
            header,
            text="  Route tablosu ve ağ topolojisi",
            foreground=self.secondary_text,
            font=("Segoe UI", 9)
        ).pack(
            side=tk.LEFT
        )

        # -----------------------------------------------------
        # TOOLBAR
        # -----------------------------------------------------

        toolbar = ttk.Frame(
            self.root,
            padding=(12, 5)
        )
        toolbar.pack(
            fill=tk.X
        )

        ttk.Label(
            toolbar,
            text="Adres ailesi:"
        ).pack(side=tk.LEFT)

        ip_combo = ttk.Combobox(
            toolbar,
            textvariable=self.ip_version,
            values=("IPv4", "IPv6", "Tümü"),
            width=8,
            state="readonly"
        )

        ip_combo.pack(
            side=tk.LEFT,
            padx=(5, 15)
        )

        ip_combo.bind(
            "<<ComboboxSelected>>",
            lambda e: self.refresh_routes()
        )

        self.refresh_button = ttk.Button(
            toolbar,
            text="Yenile",
            command=self.refresh_routes
        )

        self.refresh_button.pack(
            side=tk.LEFT,
            padx=3
        )

        ttk.Checkbutton(
            toolbar,
            text="Otomatik yenile",
            variable=self.auto_refresh,
            command=self.update_timer
        ).pack(
            side=tk.LEFT,
            padx=(15, 5)
        )

        ttk.Label(
            toolbar,
            text="Aralık:"
        ).pack(side=tk.LEFT)

        interval_combo = ttk.Combobox(
            toolbar,
            textvariable=self.refresh_seconds,
            values=(1, 2, 5, 10, 30, 60),
            width=5,
            state="readonly"
        )

        interval_combo.pack(
            side=tk.LEFT,
            padx=5
        )

        interval_combo.bind(
            "<<ComboboxSelected>>",
            lambda e: self.update_timer()
        )

        ttk.Button(
            toolbar,
            text="Grafiği sıfırla",
            command=self.reset_graph
        ).pack(
            side=tk.RIGHT,
            padx=3
        )

        # -----------------------------------------------------
        # MAIN
        # -----------------------------------------------------

        main = ttk.PanedWindow(
            self.root,
            orient=tk.HORIZONTAL
        )

        main.pack(
            fill=tk.BOTH,
            expand=True,
            padx=10,
            pady=5
        )

        # -----------------------------------------------------
        # ROUTE TABLE
        # -----------------------------------------------------

        left = ttk.Frame(main)

        ttk.Label(
            left,
            text="Route Tablosu",
            font=("Segoe UI", 11, "bold")
        ).pack(
            anchor=tk.W,
            pady=(0, 5)
        )

        table_frame = ttk.Frame(left)
        table_frame.pack(
            fill=tk.BOTH,
            expand=True
        )

        columns = (
            "destination",
            "gateway",
            "interface",
            "metric",
            "protocol",
            "state"
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        headings = {
            "destination": "Hedef",
            "gateway": "Gateway",
            "interface": "Arayüz",
            "metric": "Metric",
            "protocol": "Protokol",
            "state": "Durum"
        }

        widths = {
            "destination": 175,
            "gateway": 145,
            "interface": 150,
            "metric": 70,
            "protocol": 100,
            "state": 100
        }

        for col in columns:

            self.tree.heading(
                col,
                text=headings[col]
            )

            self.tree.column(
                col,
                width=widths[col],
                anchor=tk.W
            )

        yscroll = ttk.Scrollbar(
            table_frame,
            orient=tk.VERTICAL,
            command=self.tree.yview
        )

        xscroll = ttk.Scrollbar(
            table_frame,
            orient=tk.HORIZONTAL,
            command=self.tree.xview
        )

        self.tree.configure(
            yscrollcommand=yscroll.set,
            xscrollcommand=xscroll.set
        )

        self.tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        yscroll.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        xscroll.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        table_frame.rowconfigure(
            0,
            weight=1
        )

        table_frame.columnconfigure(
            0,
            weight=1
        )

        self.tree.bind(
            "<<TreeviewSelect>>",
            self.route_selected
        )

        main.add(
            left,
            weight=1
        )

        # -----------------------------------------------------
        # GRAPH
        # -----------------------------------------------------

        right = ttk.Frame(main)

        graph_header = ttk.Frame(right)
        graph_header.pack(
            fill=tk.X,
            pady=(0, 5)
        )

        ttk.Label(
            graph_header,
            text="Routing Topolojisi",
            font=("Segoe UI", 11, "bold")
        ).pack(
            side=tk.LEFT
        )

        ttk.Label(
            graph_header,
            text="  Fare tekerleği: yakınlaştır / uzaklaştır   •   Sürükle: taşı",
            foreground=self.secondary_text
        ).pack(
            side=tk.LEFT,
            padx=10
        )

        # Canvas + scrollbar
        canvas_frame = ttk.Frame(right)
        canvas_frame.pack(
            fill=tk.BOTH,
            expand=True
        )

        self.canvas = tk.Canvas(
            canvas_frame,
            background=self.bg,
            highlightthickness=1,
            highlightbackground=self.border
        )

        self.canvas.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

        self.vscroll = ttk.Scrollbar(
            canvas_frame,
            orient=tk.VERTICAL,
            command=self.canvas.yview
        )

        self.vscroll.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )

        self.hscroll = ttk.Scrollbar(
            right,
            orient=tk.HORIZONTAL,
            command=self.canvas.xview
        )

        self.hscroll.pack(
            fill=tk.X
        )

        self.canvas.configure(
            xscrollcommand=self.hscroll.set,
            yscrollcommand=self.vscroll.set
        )

        main.add(
            right,
            weight=2
        )

        # -----------------------------------------------------
        # STATUS BAR
        # -----------------------------------------------------

        status = ttk.Frame(
            self.root,
            padding=(10, 4)
        )

        status.pack(
            fill=tk.X
        )

        self.route_status = ttk.Label(
            status,
            text="Route: 0"
        )

        self.route_status.pack(
            side=tk.LEFT
        )

        self.interface_status = ttk.Label(
            status,
            text="Arayüz: 0"
        )

        self.interface_status.pack(
            side=tk.LEFT,
            padx=20
        )

        self.gateway_status = ttk.Label(
            status,
            text="Gateway: 0"
        )

        self.gateway_status.pack(
            side=tk.LEFT
        )

        self.last_update = ttk.Label(
            status,
            text=""
        )

        self.last_update.pack(
            side=tk.RIGHT
        )

        # -----------------------------------------------------
        # CANVAS EVENTS
        # -----------------------------------------------------

        self.canvas.bind(
            "<ButtonPress-1>",
            self.start_pan
        )

        self.canvas.bind(
            "<B1-Motion>",
            self.move_pan
        )

        self.canvas.bind(
            "<ButtonRelease-1>",
            self.end_pan
        )

        self.canvas.bind(
            "<MouseWheel>",
            self.zoom_graph
        )

        self.canvas.bind(
            "<Button-4>",
            self.zoom_graph
        )

        self.canvas.bind(
            "<Button-5>",
            self.zoom_graph
        )

    # =========================================================
    # POWERSHELL
    # =========================================================

    def get_routes(self):

        version = self.ip_version.get()

        if version == "IPv4":
            family = "IPv4"

        elif version == "IPv6":
            family = "IPv6"

        else:
            family = None

        properties = (
            "DestinationPrefix,"
            "NextHop,"
            "InterfaceAlias,"
            "InterfaceIndex,"
            "RouteMetric,"
            "Protocol,"
            "State"
        )

        if family:

            ps = (
                f"$OutputEncoding = [Console]::OutputEncoding = "
                f"[System.Text.UTF8Encoding]::new($false); "
                f"Get-NetRoute -AddressFamily {family} | "
                f"Select-Object {properties} | "
                f"ConvertTo-Json -Compress"
            )

        else:

            ps = (
                f"$OutputEncoding = [Console]::OutputEncoding = "
                f"[System.Text.UTF8Encoding]::new($false); "
                f"Get-NetRoute | "
                f"Select-Object {properties} | "
                f"ConvertTo-Json -Compress"
            )

        command = [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps
        ]

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        if result.returncode != 0:

            error = result.stderr.decode(
                "utf-8",
                errors="replace"
            )

            raise RuntimeError(
                error.strip()
                or "Get-NetRoute çalıştırılamadı."
            )

        output = result.stdout.decode(
            "utf-8",
            errors="replace"
        ).strip()

        if not output:
            return []

        data = json.loads(output)

        if isinstance(data, dict):
            data = [data]

        return data

    # =========================================================
    # REFRESH
    # =========================================================

    def refresh_routes(self):

        if self.refresh_running:
            return

        self.refresh_running = True

        self.refresh_button.config(
            state=tk.DISABLED
        )

        self.last_update.config(
            text="Route tablosu okunuyor..."
        )

        worker = threading.Thread(
            target=self._load_routes,
            daemon=True
        )

        worker.start()

    def _load_routes(self):

        try:

            routes = self.get_routes()

            if not self.closed:

                self.root.after(
                    0,
                    self.update_routes,
                    routes
                )

        except Exception as exc:

            if not self.closed:

                self.root.after(
                    0,
                    self.show_error,
                    str(exc)
                )

        finally:

            if not self.closed:

                self.root.after(
                    0,
                    self.refresh_finished
                )

    def refresh_finished(self):

        self.refresh_running = False

        self.refresh_button.config(
            state=tk.NORMAL
        )

        self.update_timer()

    # =========================================================
    # TIMER
    # =========================================================

    def update_timer(self):

        if self.refresh_job is not None:

            try:
                self.root.after_cancel(
                    self.refresh_job
                )
            except tk.TclError:
                pass

            self.refresh_job = None

        if not self.auto_refresh.get():
            return

        try:
            seconds = int(
                self.refresh_seconds.get()
            )
        except Exception:
            seconds = 5

        seconds = max(
            1,
            seconds
        )

        self.refresh_job = self.root.after(
            seconds * 1000,
            self.timer_callback
        )

    def timer_callback(self):

        self.refresh_job = None

        if self.auto_refresh.get():

            self.refresh_routes()

    # =========================================================
    # UPDATE DATA
    # =========================================================

    def update_routes(self, routes):

        self.routes = routes

        self.tree.delete(
            *self.tree.get_children()
        )

        # -----------------------------------------------------
        # SORT
        # -----------------------------------------------------

        routes = sorted(
            routes,
            key=self.route_sort_key
        )

        self.routes = routes

        # -----------------------------------------------------
        # TABLE
        # -----------------------------------------------------

        for index, route in enumerate(routes):

            destination = self.value(
                route,
                "DestinationPrefix"
            )

            gateway = self.value(
                route,
                "NextHop"
            )

            interface = self.value(
                route,
                "InterfaceAlias"
            )

            metric = self.value(
                route,
                "RouteMetric"
            )

            protocol = self.value(
                route,
                "Protocol"
            )

            state = self.value(
                route,
                "State"
            )

            item = self.tree.insert(
                "",
                tk.END,
                iid=str(index),
                values=(
                    destination,
                    gateway,
                    interface,
                    metric,
                    protocol,
                    state
                )
            )

            # Default route
            if destination in (
                "0.0.0.0/0",
                "::/0"
            ):
                self.tree.item(
                    item,
                    tags=("default",)
                )

        self.tree.tag_configure(
            "default",
            background="#fff1f2"
        )

        # -----------------------------------------------------
        # STATISTICS
        # -----------------------------------------------------

        interfaces = {
            self.value(r, "InterfaceAlias")
            for r in routes
            if self.value(r, "InterfaceAlias")
        }

        gateways = {
            self.value(r, "NextHop")
            for r in routes
            if self.value(r, "NextHop")
            not in ("", "0.0.0.0", "::")
        }

        self.route_status.config(
            text=f"Route: {len(routes)}"
        )

        self.interface_status.config(
            text=f"Arayüz: {len(interfaces)}"
        )

        self.gateway_status.config(
            text=f"Gateway: {len(gateways)}"
        )

        self.last_update.config(
            text=f"Son güncelleme: {time.strftime('%H:%M:%S')}"
        )

        self.draw_graph()

    # =========================================================
    # SORT
    # =========================================================

    @staticmethod
    def route_sort_key(route):

        destination = str(
            route.get("DestinationPrefix") or ""
        )

        if destination in (
            "0.0.0.0/0",
            "::/0"
        ):
            return (
                0,
                ""
            )

        return (
            1,
            destination
        )

    # =========================================================
    # GRAPH
    # =========================================================

    def draw_graph(self):

        self.canvas.delete("all")

        if not self.routes:
            return

        # -----------------------------------------------------
        # GROUPS
        # -----------------------------------------------------

        interfaces = {}
        gateways = {}
        destinations = {}

        for route in self.routes:

            interface = self.value(
                route,
                "InterfaceAlias"
            )

            gateway = self.value(
                route,
                "NextHop"
            )

            destination = self.value(
                route,
                "DestinationPrefix"
            )

            if not interface:
                interface = "Bilinmeyen arayüz"

            if not gateway:
                gateway = "Doğrudan bağlantı"

            if not destination:
                continue

            interfaces.setdefault(
                interface,
                []
            ).append(route)

            gateways.setdefault(
                gateway,
                []
            ).append(route)

            destinations.setdefault(
                destination,
                []
            ).append(route)

        interface_names = sorted(
            interfaces.keys(),
            key=str.casefold
        )

        gateway_names = sorted(
            gateways.keys(),
            key=str.casefold
        )

        destination_names = sorted(
            destinations.keys(),
            key=self.destination_sort_key
        )

        # -----------------------------------------------------
        # GRAPH DIMENSIONS
        # -----------------------------------------------------

        node_w = 210
        node_h = 68

        column_gap = 180
        row_gap = 28

        max_rows = max(
            len(interface_names),
            len(gateway_names),
            len(destination_names),
            1
        )

        graph_width = (
            node_w * 3 +
            column_gap * 2 +
            150
        )

        graph_height = max(
            700,
            100 + max_rows * (
                node_h + row_gap
            )
        )

        # -----------------------------------------------------
        # POSITIONS
        # -----------------------------------------------------

        positions_interface = self.calculate_positions(
            interface_names,
            150,
            node_h,
            row_gap
        )

        positions_gateway = self.calculate_positions(
            gateway_names,
            150 + node_w + column_gap,
            node_h,
            row_gap
        )

        positions_destination = self.calculate_positions(
            destination_names,
            150 + (node_w + column_gap) * 2,
            node_h,
            row_gap
        )

        # -----------------------------------------------------
        # CONNECTIONS
        # -----------------------------------------------------

        # Interface -> Gateway
        interface_gateway = set()

        # Gateway -> Destination
        gateway_destination = set()

        for route in self.routes:

            interface = self.value(
                route,
                "InterfaceAlias"
            ) or "Bilinmeyen arayüz"

            gateway = self.value(
                route,
                "NextHop"
            ) or "Doğrudan bağlantı"

            destination = self.value(
                route,
                "DestinationPrefix"
            )

            if not destination:
                continue

            interface_gateway.add(
                (
                    interface,
                    gateway
                )
            )

            gateway_destination.add(
                (
                    gateway,
                    destination
                )
            )

        # -----------------------------------------------------
        # DRAW CONNECTIONS FIRST
        # -----------------------------------------------------

        for interface, gateway in interface_gateway:

            if (
                interface in positions_interface and
                gateway in positions_gateway
            ):

                self.draw_connection(
                    positions_interface[interface],
                    positions_gateway[gateway],
                    self.interface_border
                )

        for gateway, destination in gateway_destination:

            if (
                gateway in positions_gateway and
                destination in positions_destination
            ):

                color = self.line_color

                if destination in (
                    "0.0.0.0/0",
                    "::/0"
                ):
                    color = self.default_border

                self.draw_connection(
                    positions_gateway[gateway],
                    positions_destination[destination],
                    color
                )

        # -----------------------------------------------------
        # COLUMN HEADERS
        # -----------------------------------------------------

        self.draw_column_header(
            150,
            35,
            "ARAYÜZLER",
            self.interface_border
        )

        self.draw_column_header(
            150 + node_w + column_gap,
            35,
            "NEXT-HOP / GATEWAY",
            self.gateway_border
        )

        self.draw_column_header(
            150 + (node_w + column_gap) * 2,
            35,
            "HEDEF AĞLAR",
            self.destination_border
        )

        # -----------------------------------------------------
        # NODES
        # -----------------------------------------------------

        for name, pos in positions_interface.items():

            count = len(
                interfaces[name]
            )

            self.draw_node(
                pos,
                name,
                f"{count} route",
                "interface"
            )

        for name, pos in positions_gateway.items():

            count = len(
                gateways[name]
            )

            node_type = "gateway"

            if name == "Doğrudan bağlantı":
                node_type = "direct"

            self.draw_node(
                pos,
                name,
                f"{count} route",
                node_type
            )

        for name, pos in positions_destination.items():

            count = len(
                destinations[name]
            )

            node_type = "destination"

            if name in (
                "0.0.0.0/0",
                "::/0"
            ):
                node_type = "default"

            self.draw_node(
                pos,
                name,
                f"{count} route",
                node_type
            )

        # -----------------------------------------------------
        # LEGEND
        # -----------------------------------------------------

        self.draw_legend()

        # -----------------------------------------------------
        # SCROLL REGION
        # -----------------------------------------------------

        self.canvas.configure(
            scrollregion=(
                0,
                0,
                graph_width,
                graph_height
            )
        )

        self.canvas.xview_moveto(0)
        self.canvas.yview_moveto(0)

    # =========================================================
    # POSITIONS
    # =========================================================

    def calculate_positions(
        self,
        names,
        x,
        node_h,
        row_gap
    ):

        positions = {}

        if not names:
            return positions

        total_height = (
            len(names) * node_h +
            (len(names) - 1) * row_gap
        )

        start_y = max(
            100,
            450 - total_height / 2
        )

        for index, name in enumerate(names):

            y = (
                start_y +
                index * (
                    node_h + row_gap
                )
            )

            positions[name] = (
                x,
                y
            )

        return positions

    # =========================================================
    # NODE
    # =========================================================

    def draw_node(
        self,
        position,
        title,
        subtitle,
        node_type
    ):

        x, y = position

        w = 210
        h = 68

        if node_type == "interface":

            fill = self.interface_color
            border = self.interface_border
            icon = "↔"

        elif node_type == "gateway":

            fill = self.gateway_color
            border = self.gateway_border
            icon = "◆"

        elif node_type == "direct":

            fill = "#ecfdf5"
            border = "#10b981"
            icon = "●"

        elif node_type == "default":

            fill = self.default_color
            border = self.default_border
            icon = "★"

        else:

            fill = self.destination_color
            border = self.destination_border
            icon = "▣"

        x1 = x - w / 2
        y1 = y - h / 2
        x2 = x + w / 2
        y2 = y + h / 2

        # Shadow
        self.canvas.create_rectangle(
            x1 + 3,
            y1 + 3,
            x2 + 3,
            y2 + 3,
            fill="#d8dee8",
            outline=""
        )

        # Main node
        self.canvas.create_rectangle(
            x1,
            y1,
            x2,
            y2,
            fill=fill,
            outline=border,
            width=2
        )

        # Icon
        self.canvas.create_text(
            x1 + 22,
            y,
            text=icon,
            font=(
                "Segoe UI Symbol",
                16,
                "bold"
            ),
            fill=border
        )

        # Title
        self.canvas.create_text(
            x + 12,
            y - 10,
            text=self.fit_text(
                title,
                27
            ),
            font=(
                "Segoe UI",
                9,
                "bold"
            ),
            fill=self.text_color
        )

        # Subtitle
        self.canvas.create_text(
            x + 12,
            y + 13,
            text=subtitle,
            font=(
                "Segoe UI",
                8
            ),
            fill=self.secondary_text
        )

    # =========================================================
    # CONNECTION
    # =========================================================

    def draw_connection(
        self,
        source,
        target,
        color
    ):

        sx, sy = source
        tx, ty = target

        node_w = 210

        x1 = sx + node_w / 2
        y1 = sy

        x2 = tx - node_w / 2
        y2 = ty

        middle_x = (
            x1 + x2
        ) / 2

        self.canvas.create_line(
            x1,
            y1,
            middle_x,
            y1,
            middle_x,
            y2,
            x2,
            y2,
            fill=color,
            width=2,
            arrow=tk.LAST,
            smooth=True
        )

    # =========================================================
    # COLUMN HEADER
    # =========================================================

    def draw_column_header(
        self,
        x,
        y,
        text,
        color
    ):

        self.canvas.create_text(
            x,
            y,
            text=text,
            font=(
                "Segoe UI",
                9,
                "bold"
            ),
            fill=color
        )

    # =========================================================
    # LEGEND
    # =========================================================

    def draw_legend(self):

        x = 30
        y = 650

        self.canvas.create_text(
            x,
            y,
            anchor=tk.W,
            text="Açıklama",
            font=(
                "Segoe UI",
                9,
                "bold"
            ),
            fill=self.text_color
        )

        legend = [
            (
                self.interface_color,
                self.interface_border,
                "Arayüz"
            ),
            (
                self.gateway_color,
                self.gateway_border,
                "Gateway"
            ),
            (
                self.destination_color,
                self.destination_border,
                "Hedef ağ"
            ),
            (
                self.default_color,
                self.default_border,
                "Default route"
            )
        ]

        for i, (
            fill,
            border,
            text
        ) in enumerate(legend):

            yy = y + 25 + i * 25

            self.canvas.create_rectangle(
                x,
                yy - 7,
                x + 14,
                yy + 7,
                fill=fill,
                outline=border
            )

            self.canvas.create_text(
                x + 22,
                yy,
                anchor=tk.W,
                text=text,
                font=("Segoe UI", 8),
                fill=self.secondary_text
            )

    # =========================================================
    # TREE SELECTION
    # =========================================================

    def route_selected(self, event=None):

        selection = self.tree.selection()

        if not selection:
            return

        try:

            index = int(
                selection[0]
            )

            if 0 <= index < len(self.routes):

                self.selected_route = (
                    self.routes[index]
                )

        except Exception:
            return

    # =========================================================
    # PAN
    # =========================================================

    def start_pan(self, event):

        self.drag_start = (
            event.x,
            event.y
        )

    def move_pan(self, event):

        if self.drag_start is None:
            return

        dx = (
            event.x -
            self.drag_start[0]
        )

        dy = (
            event.y -
            self.drag_start[1]
        )

        self.canvas.xview_scroll(
            int(-dx / 2),
            "units"
        )

        self.canvas.yview_scroll(
            int(-dy / 2),
            "units"
        )

        self.drag_start = (
            event.x,
            event.y
        )

    def end_pan(self, event):

        self.drag_start = None

    # =========================================================
    # ZOOM
    # =========================================================

    def zoom_graph(self, event):

        # Tk Canvas zoom yerine ölçekli redraw
        # yapılmadığı için scrollbar ile çalışıyoruz.
        #
        # Burada aşırı zoom yapılmasını engelliyoruz.

        if hasattr(event, "delta"):

            if event.delta > 0:
                self.canvas.scale(
                    "all",
                    event.x,
                    event.y,
                    1.1,
                    1.1
                )
            else:
                self.canvas.scale(
                    "all",
                    event.x,
                    event.y,
                    0.9,
                    0.9
                )

        elif event.num == 4:

            self.canvas.scale(
                "all",
                event.x,
                event.y,
                1.1,
                1.1
            )

        elif event.num == 5:

            self.canvas.scale(
                "all",
                event.x,
                event.y,
                0.9,
                0.9
            )

    # =========================================================
    # RESET
    # =========================================================

    def reset_graph(self):

        self.draw_graph()

    # =========================================================
    # UTILITY
    # =========================================================

    @staticmethod
    def value(data, key):

        value = data.get(key)

        if value is None:
            return ""

        return str(value)

    @staticmethod
    def fit_text(text, length):

        text = str(text)

        if len(text) <= length:
            return text

        return text[:length - 3] + "..."

    @staticmethod
    def destination_sort_key(value):

        value = str(value)

        if value in (
            "0.0.0.0/0",
            "::/0"
        ):
            return (
                0,
                ""
            )

        # IPv4 prefix uzunluğunu dikkate al
        match = re.match(
            r".*/(\d+)$",
            value
        )

        if match:

            try:
                prefix = int(
                    match.group(1)
                )

                return (
                    1,
                    -prefix,
                    value
                )

            except ValueError:
                pass

        return (
            2,
            value
        )

    # =========================================================
    # ERROR
    # =========================================================

    def show_error(self, error):

        self.refresh_running = False

        self.refresh_button.config(
            state=tk.NORMAL
        )

        self.last_update.config(
            text="Route okunamadı"
        )

        messagebox.showerror(
            "Hata",
            error
        )

        self.update_timer()

    # =========================================================
    # CLOSE
    # =========================================================

    def close(self):

        self.closed = True

        if self.refresh_job is not None:

            try:

                self.root.after_cancel(
                    self.refresh_job
                )

            except tk.TclError:
                pass

            self.refresh_job = None

        self.root.destroy()


# =============================================================
# MAIN
# =============================================================

def main():

    root = tk.Tk()

    # Windows 11 DPI
    try:
        root.tk.call(
            "tk",
            "scaling",
            1.0
        )
    except tk.TclError:
        pass

    RouteVisualizer(root)

    root.mainloop()


if __name__ == "__main__":
    main()