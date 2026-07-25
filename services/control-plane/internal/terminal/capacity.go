package terminal

func (m *Manager) requireTabCapacityLocked(ownerID, workspaceID string) error {
	ownerTabs, workspaceTabs := 0, 0
	for _, tab := range m.tabs {
		if tab.ownerID == ownerID {
			ownerTabs++
			if tab.workspaceID == workspaceID {
				workspaceTabs++
			}
		}
	}
	if len(m.tabs) >= maxRegisteredTabsGlobal || ownerTabs >= maxRegisteredTabsPerOwner || workspaceTabs >= maxRegisteredTabsPerWorkspace {
		return ErrTerminalCapacity
	}
	return nil
}

func (m *Manager) requireCredentialCapacityLocked(ownerID, deviceID string, tabID TabID, consumedReconnect *[32]byte) error {
	ticketOwner, ticketDevice, ticketTab := 0, 0, 0
	for _, record := range m.tickets {
		if record.ownerID == ownerID {
			ticketOwner++
			if record.deviceID == deviceID {
				ticketDevice++
			}
		}
		if record.tabID == tabID {
			ticketTab++
		}
	}
	if len(m.tickets) >= maxUnusedTicketsGlobal ||
		ticketOwner >= maxUnusedTicketsPerOwner ||
		ticketDevice >= maxUnusedTicketsPerDevice ||
		ticketTab >= maxUnusedTicketsPerTab {
		return ErrTerminalCapacity
	}

	reconnectTotal, reconnectOwner, reconnectDevice, reconnectTab := 0, 0, 0, 0
	for key, record := range m.reconnects {
		if consumedReconnect != nil && key == *consumedReconnect {
			continue
		}
		reconnectTotal++
		if record.ownerID == ownerID {
			reconnectOwner++
			if record.deviceID == deviceID {
				reconnectDevice++
			}
		}
		if record.tabID == tabID {
			reconnectTab++
		}
	}
	if reconnectTotal >= maxReconnectsGlobal ||
		reconnectOwner >= maxReconnectsPerOwner ||
		reconnectDevice >= maxReconnectsPerDevice ||
		reconnectTab >= maxReconnectsPerTab {
		return ErrTerminalCapacity
	}
	return nil
}

// reserveSubscriberLocked records an admitted connection before its channels
// are allocated. The maps cannot grow beyond maxSubscribersGlobal because
// zero-count keys are deleted on release.
func (m *Manager) reserveSubscriberLocked(record ticketRecord) error {
	device := ownerDevice{ownerID: record.ownerID, deviceID: record.deviceID}
	if m.subscribers >= maxSubscribersGlobal ||
		m.subscribersByOwner[record.ownerID] >= maxSubscribersPerOwner ||
		m.subscribersByDevice[device] >= maxSubscribersPerDevice ||
		m.subscribersByTab[record.tabID] >= maxSubscribersPerTab {
		return ErrTerminalCapacity
	}
	m.subscribers++
	m.subscribersByOwner[record.ownerID]++
	m.subscribersByDevice[device]++
	m.subscribersByTab[record.tabID]++
	return nil
}

func (m *Manager) releaseSubscriberLocked(record ticketRecord) {
	device := ownerDevice{ownerID: record.ownerID, deviceID: record.deviceID}
	if m.subscribers == 0 || m.subscribersByOwner[record.ownerID] == 0 ||
		m.subscribersByDevice[device] == 0 || m.subscribersByTab[record.tabID] == 0 {
		panic("terminal subscriber accounting underflow")
	}
	m.subscribers--
	decrementStringCount(m.subscribersByOwner, record.ownerID)
	decrementOwnerDeviceCount(m.subscribersByDevice, device)
	decrementTabCount(m.subscribersByTab, record.tabID)
}

func decrementStringCount(values map[string]int, key string) {
	values[key]--
	if values[key] == 0 {
		delete(values, key)
	}
}

func decrementOwnerDeviceCount(values map[ownerDevice]int, key ownerDevice) {
	values[key]--
	if values[key] == 0 {
		delete(values, key)
	}
}

func decrementTabCount(values map[TabID]int, key TabID) {
	values[key]--
	if values[key] == 0 {
		delete(values, key)
	}
}

func (m *Manager) unsubscribe(admission admittedConnection) {
	if !admission.tab.unsubscribe(admission.subscriberID) {
		return
	}
	m.mu.Lock()
	m.releaseSubscriberLocked(admission.record)
	m.mu.Unlock()
}
