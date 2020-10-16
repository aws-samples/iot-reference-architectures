package com.awslabs.iatt.spe.serverless.gwt.client.shell;

import elemental2.dom.HTMLDivElement;
import org.dominokit.domino.api.client.annotations.UiView;
import org.dominokit.domino.api.client.mvp.slots.IsSlot;
import org.dominokit.domino.ui.layout.Layout;
import org.dominokit.domino.ui.tabs.Tab;
import org.dominokit.domino.ui.tabs.TabsPanel;
import org.dominokit.domino.view.BaseElementView;
import org.dominokit.domino.view.slots.SingleElementSlot;

@UiView(presentable = ShellProxy.class)
public class ShellViewImpl extends BaseElementView<HTMLDivElement> implements ShellView {
    private ShellUiHandlers uiHandlers;
    private Layout layout;
    private Tab createAndValidateTab;
    private Tab attributionTab;
    private Tab inspectTab;
    private Tab testTab;
    private TabsPanel tabsPanel;

    @Override
    protected HTMLDivElement init() {
        createAndValidateTab = Tab.create(ShellSlots.CREATE_AND_VALIDATE_TAB, "Create and Validate");
        attributionTab = Tab.create(ShellSlots.ATTRIBUTION_TAB, "Attribution");
        inspectTab = Tab.create(ShellSlots.INSPECT_TAB, "Inspect");
        testTab = Tab.create(ShellSlots.TEST_TAB, "Test");
        tabsPanel = TabsPanel.create();
        tabsPanel.appendChild(createAndValidateTab)
                .appendChild(attributionTab)
                .appendChild(inspectTab)
                .appendChild(testTab);

        layout = Layout.create("Partner JWT authentication demo, with attribution")
                .disableLeftPanel();

        layout.getContentPanel()
                .appendChild(tabsPanel
                        .addActivationHandler((tab, active) -> {
                                    if (active) {
                                        uiHandlers.onNavigation(tab.getKey());
                                    }
                                }
                        ));

        return layout.element();
    }

    @Override
    public void setUiHandlers(ShellUiHandlers uiHandlers) {
        this.uiHandlers = uiHandlers;
    }

    @Override
    public void activatePage(String page) {
        tabsPanel.activateByKey(page);
    }

    @Override
    public IsSlot<?> getCreateAndValidateSlot() {
        return SingleElementSlot.of(createAndValidateTab.getContentContainer());
    }

    @Override
    public IsSlot<?> getAttributionSlot() {
        return SingleElementSlot.of(attributionTab.getContentContainer());
    }

    @Override
    public IsSlot<?> getInspectSlot() {
        return SingleElementSlot.of(inspectTab.getContentContainer());
    }

    @Override
    public IsSlot<?> getTestSlot() {
        return SingleElementSlot.of(testTab.getContentContainer());
    }
}