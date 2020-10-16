package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.client.events.AttributionChangedEvent;
import com.awslabs.iatt.spe.serverless.gwt.client.events.AttributionData;
import com.google.gwt.regexp.shared.RegExp;
import elemental2.dom.HTMLDivElement;
import org.dominokit.domino.api.client.annotations.UiView;
import org.dominokit.domino.ui.cards.Card;
import org.dominokit.domino.ui.forms.FieldStyle;
import org.dominokit.domino.ui.forms.SwitchButton;
import org.dominokit.domino.ui.forms.TextBox;
import org.dominokit.domino.ui.forms.validations.ValidationResult;
import org.dominokit.domino.ui.icons.Icons;
import org.dominokit.domino.view.BaseElementView;
import org.jboss.elemento.EventType;
import org.jetbrains.annotations.NotNull;

import static com.awslabs.iatt.spe.serverless.gwt.client.BrowserHelper.danger;

@UiView(presentable = AttributionProxy.class)
public class AttributionViewImpl extends BaseElementView<HTMLDivElement> implements AttributionView {
    private final RegExp partnerNamePattern = RegExp.compile("^(\\w){1,64}$");
    private final RegExp solutionNamePattern = RegExp.compile("^(\\w){1,64}$");
    private final RegExp versionNamePattern = RegExp.compile("^([\\w\\.]){1,8}$");
    private SwitchButton attributionSwitchButton;
    private TextBox partnerNameBox;
    private TextBox solutionNameBox;
    private TextBox versionNameBox;
    private AttributionUiHandlers uiHandlers;
    private Card card;

    @Override
    protected HTMLDivElement init() {
        getAttributionSwitchButton();
        getPartnerNameBox();
        getSolutionNameBox();
        getVersionNameBox();
        toggleAttributionFields(attributionSwitchButton.getValue());

        attributionSwitchButton.addChangeHandler(value -> uiHandlers.onAttributionDataUpdated(getAttributionData()));
        partnerNameBox.addEventListener(EventType.keyup, evt -> uiHandlers.onAttributionDataUpdated(getAttributionData()));
        solutionNameBox.addEventListener(EventType.keyup, evt -> uiHandlers.onAttributionDataUpdated(getAttributionData()));
        versionNameBox.addEventListener(EventType.keyup, evt -> uiHandlers.onAttributionDataUpdated(getAttributionData()));

        this.card = Card.create("Attribution", "You can set attribution data on this tab")
                .appendChild(attributionSwitchButton)
                .appendChild(partnerNameBox)
                .appendChild(solutionNameBox)
                .appendChild(versionNameBox);

        return card.element();
    }

    @NotNull
    private AttributionChangedEvent getAttributionChangedEvent() {
        return new AttributionChangedEvent(getAttributionData());
    }

    @NotNull
    private AttributionData getAttributionData() {
        return new AttributionData(attributionSwitchButton.getValue(), partnerNameBox.getStringValue(), solutionNameBox.getStringValue(), versionNameBox.getStringValue());
    }

    private void getAttributionSwitchButton() {
        attributionSwitchButton = SwitchButton.create()
                .setOffTitle("Attribution: ")
                .setHelperText("Attribution information will be added if enabled")
                .addChangeHandler(this::toggleAttributionFields);
    }

    private void toggleAttributionFields(Boolean value) {
        partnerNameBox.setDisabled(!value);
        solutionNameBox.setDisabled(!value);
        versionNameBox.setDisabled(!value);
    }

    private void getPartnerNameBox() {
        partnerNameBox = TextBox.create("Partner name")
                .setFieldStyle(FieldStyle.ROUNDED)
                .setMaxLength(64)
                .addLeftAddOn(Icons.ALL.account_circle())
                .setHelperText("Partner name for attribution")
                .value("Partner")
                .setReadOnly(false)
                .setAutoValidation(true)
                .addValidator(() -> {
                    if (partnerNamePattern.test(partnerNameBox.getStringValue())) {
                        return ValidationResult.valid();
                    }

                    return ValidationResult.invalid("Partner name didn't match the pattern " + partnerNamePattern.getSource());
                });
    }

    private void getSolutionNameBox() {
        solutionNameBox = TextBox.create("Solution name")
                .setFieldStyle(FieldStyle.ROUNDED)
                .setMaxLength(64)
                .addLeftAddOn(Icons.ALL.chip_mdi())
                .setHelperText("Solution name for attribution")
                .value("Solution")
                .setReadOnly(false)
                .setAutoValidation(true)
                .addValidator(() -> {
                    if (solutionNameBox.isEmpty()) {
                        // Empty value is OK
                        return ValidationResult.valid();
                    }

                    if (solutionNamePattern.test(solutionNameBox.getStringValue())) {
                        return ValidationResult.valid();
                    }

                    return ValidationResult.invalid("Solution name didn't match the pattern " + solutionNamePattern.getSource());
                });
    }

    private void getVersionNameBox() {
        versionNameBox = TextBox.create("Version name")
                .setFieldStyle(FieldStyle.ROUNDED)
                .setMaxLength(8)
                .addLeftAddOn(Icons.ALL.barcode_scan_mdi())
                .setHelperText("Version name for attribution")
                .value("v1.0")
                .setReadOnly(false)
                .setAutoValidation(true)
                .addValidator(() -> {
                    if (versionNameBox.isEmpty()) {
                        // Empty value is OK
                        return ValidationResult.valid();
                    }

                    if (versionNamePattern.test(versionNameBox.getStringValue())) {
                        return ValidationResult.valid();
                    }

                    danger("Version name did not validate");
                    return ValidationResult.invalid("Version name didn't match the pattern " + versionNamePattern.getSource());
                });
    }

    @Override
    public void setUiHandlers(AttributionUiHandlers uiHandlers) {
        this.uiHandlers = uiHandlers;
    }
}
