import 'package:flutter/material.dart';

import '../theme.dart';
import 'dashboard.dart';
import 'tickets_list.dart';
import 'settings.dart';
import 'incidents.dart';
import 'origin_health.dart';
import 'findings.dart';

class HomeShell extends StatefulWidget {
  const HomeShell({super.key});
  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _index = 0;
  final _drawerKey = GlobalKey<ScaffoldState>();

  static const _pages = [
    DashboardScreen(),
    TicketsListScreen(),
    SettingsScreen(),
  ];

  static const _titles = ['Dashboard', 'Tickets', 'Settings'];

  void _openDrawer() => _drawerKey.currentState?.openDrawer();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      key: _drawerKey,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.menu),
          onPressed: _openDrawer,
          tooltip: 'Menu',
        ),
        title: Row(children: [
          Container(
            width: 28, height: 28,
            decoration: BoxDecoration(
              color: redotRed,
              borderRadius: BorderRadius.circular(6),
            ),
            child: const Icon(Icons.shield, color: Colors.white, size: 18),
          ),
          const SizedBox(width: 10),
          Text(_titles[_index]),
        ]),
      ),
      drawer: _drawer(context),
      body: SafeArea(child: _pages[_index]),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index,
        onDestinationSelected: (i) => setState(() => _index = i),
        backgroundColor: Colors.white,
        indicatorColor: redotRed.withOpacity(0.12),
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.dashboard_outlined),
            selectedIcon: Icon(Icons.dashboard, color: redotRed),
            label: 'Dashboard',
          ),
          NavigationDestination(
            icon: Icon(Icons.confirmation_num_outlined),
            selectedIcon: Icon(Icons.confirmation_num, color: redotRed),
            label: 'Tickets',
          ),
          NavigationDestination(
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings, color: redotRed),
            label: 'Settings',
          ),
        ],
      ),
    );
  }

  Widget _drawer(BuildContext context) {
    Widget item(IconData ic, String label, VoidCallback onTap) => ListTile(
      leading: Icon(ic, color: redotRed),
      title: Text(label),
      onTap: () { Navigator.of(context).pop(); onTap(); },
    );

    return Drawer(
      child: SafeArea(
        child: ListView(
          padding: EdgeInsets.zero,
          children: [
            Container(
              padding: const EdgeInsets.fromLTRB(20, 24, 20, 24),
              decoration: const BoxDecoration(color: redotRed),
              child: Row(children: [
                Container(
                  width: 44, height: 44,
                  decoration: BoxDecoration(
                    color: Colors.white.withOpacity(0.18),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: const Icon(Icons.shield, color: Colors.white, size: 24),
                ),
                const SizedBox(width: 12),
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Redot Sentinel',
                          style: TextStyle(color: Colors.white,
                              fontSize: 16, fontWeight: FontWeight.w700)),
                      SizedBox(height: 2),
                      Text('MMWSS monitoring',
                          style: TextStyle(color: Colors.white70, fontSize: 12)),
                    ],
                  ),
                ),
              ]),
            ),
            item(Icons.dashboard, 'Dashboard', () => setState(() => _index = 0)),
            item(Icons.confirmation_num, 'Tickets', () => setState(() => _index = 1)),
            const Divider(),
            item(Icons.warning_amber, 'Incidents', () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const IncidentsScreen()))),
            item(Icons.dns, 'Origin health', () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const OriginHealthScreen()))),
            item(Icons.shield, 'Scanner findings', () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const FindingsScreen()))),
            const Divider(),
            item(Icons.settings, 'Settings', () => setState(() => _index = 2)),
          ],
        ),
      ),
    );
  }
}
