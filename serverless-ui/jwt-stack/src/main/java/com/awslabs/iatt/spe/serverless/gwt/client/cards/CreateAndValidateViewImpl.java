package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.client.components.CodeCard;
import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import elemental2.dom.Event;
import elemental2.dom.HTMLDivElement;
import org.dominokit.domino.api.client.annotations.UiView;
import org.dominokit.domino.ui.button.Button;
import org.dominokit.domino.ui.button.ButtonSize;
import org.dominokit.domino.ui.cards.Card;
import org.dominokit.domino.ui.forms.FieldStyle;
import org.dominokit.domino.ui.forms.TextBox;
import org.dominokit.domino.ui.header.BlockHeader;
import org.dominokit.domino.ui.icons.Icons;
import org.dominokit.domino.ui.loaders.Loader;
import org.dominokit.domino.ui.loaders.LoaderEffect;
import org.dominokit.domino.ui.sliders.Slider;
import org.dominokit.domino.ui.utils.BaseDominoElement;
import org.dominokit.domino.view.BaseElementView;
import org.jboss.elemento.Elements;
import org.jboss.elemento.EventType;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.awslabs.iatt.spe.serverless.gwt.client.BrowserHelper.danger;
import static com.awslabs.iatt.spe.serverless.gwt.shared.Helpers.bytesToHex;
import static org.dominokit.domino.ui.style.Unit.px;

@UiView(presentable = CreateAndValidateProxy.class)
public class CreateAndValidateViewImpl extends BaseElementView<HTMLDivElement> implements CreateAndValidateView {
    public static final int ICCID_LENGTH = 19;
    public static final String GENERATE_JWT = "Generate JWT";
    public static final String MARGIN = px.of(5);
    public static final String MIN_WIDTH = px.of(200);
    private MessageDigest md5;
    private TextBox deviceIdBox;
    private TextBox iccidBox;
    private Button generateJwtButton;
    private CodeCard jwtCodeCard;
    private int expirationTimeMs;
    private Slider expirationSlider;
    private int expirationTimeSeconds;
    private BlockHeader expirationHeader;
    private Button validateJwtButton;
    private CreateAndValidateUiHandlers uiHandlers;
    private Optional<JwtResponse> optionalJwtResponse = Optional.empty();

    @Override
    protected HTMLDivElement init() {
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        getDeviceIdBox();
        getIccidBox();
        getExpirationSlider();
        getGenerateJwtButton();
        getValidateJwtButton();
        getJwtCard();
        invalidateJwt();

        deviceIdBox.addEventListener(EventType.keyup, event -> uiHandlers.invalidate());

        return Card.create("Create and validate", "You can create and validate JWTs on this tab")
                .appendChild(deviceIdBox)
                .appendChild(iccidBox)
                .appendChild(expirationHeader)
                .appendChild(expirationSlider)
                .appendChild(generateJwtButton)
                .appendChild(validateJwtButton)
                .appendChild(Elements.br())
                .appendChild(Elements.br())
                .appendChild(jwtCodeCard)
                .element();
    }

    private void getValidateJwtButton() {
        validateJwtButton = Button.createPrimary("Validate JWT")
                .setSize(ButtonSize.LARGE)
                .style()
                .setMargin(MARGIN)
                .setMinWidth(MIN_WIDTH)
                .get()
                .addClickListener(this::handleValidateJwtClick)
                .hide();
    }

    private void handleValidateJwtClick(Event event) {
        if (!optionalJwtResponse.isPresent()) {
            danger("No JWT was created yet. First create one with the '" + GENERATE_JWT + "' button");

            return;
        }

        JwtResponse jwtResponse = optionalJwtResponse.get();

        Loader loader = Loader.create(validateJwtButton, LoaderEffect.PULSE)
                .setLoadingText("Validating ...")
                .start();

        uiHandlers.validateJwt(loader, jwtResponse.token);
    }

    private void getExpirationSlider() {
        expirationSlider = Slider.create(120, 10)
                .setStep(10)
                .setValue(120)
                .withThumb()
                .addChangeHandler(this::updateExpirationTime);

        expirationHeader = BlockHeader.create("");

        // Initialize the expiration time
        updateExpirationTime(expirationSlider.getValue());
    }

    private void updateBlockHeader() {
        expirationHeader.setTextContent("Expiration time in seconds [" + expirationTimeSeconds + "]");
    }

    private void updateExpirationTime(Double newExpirationTimeSeconds) {
        expirationTimeSeconds = newExpirationTimeSeconds.intValue();
        expirationTimeMs = expirationTimeSeconds * 1000;
        updateBlockHeader();
    }

    private void getDeviceIdBox() {
        deviceIdBox = TextBox.create("Device ID")
                .setFieldStyle(FieldStyle.ROUNDED)
                .setMaxLength(50)
                .addLeftAddOn(Icons.ALL.antenna_mdi())
                .setHelperText("Can be any value, this value is hashed to generate a repeatable ICCID value")
                .value("device001")
                .setReadOnly(false)
                .addEventListener(EventType.keyup, value -> updateFakeIccid(deviceIdBox, iccidBox));
    }

    private void getIccidBox() {
        iccidBox = TextBox.create("ICCID")
                .setFieldStyle(FieldStyle.ROUNDED)
                .addLeftAddOn(Icons.ALL.sim_mdi())
                .setHelperText("Automatically generated from the device ID")
                .value("")
                .setReadOnly(true);

        updateFakeIccid(deviceIdBox, iccidBox);
    }

    // From https://stackoverflow.com/a/3760193
    private List<String> splitEqually(String text, int size) {
        List<String> ret = new ArrayList<>((text.length() + size - 1) / size);

        for (int start = 0; start < text.length(); start += size) {
            ret.add(text.substring(start, Math.min(text.length(), start + size)));
        }

        return ret;
    }

    private void getJwtCard() {
        jwtCodeCard = CodeCard.createCodeCard("")
                .setTitle("JWT data")
                .apply(BaseDominoElement::show);
    }

    private void getGenerateJwtButton() {
        generateJwtButton = Button.createPrimary(GENERATE_JWT)
                .setSize(ButtonSize.LARGE)
                .style()
                .setMargin(MARGIN)
                .setMinWidth(MIN_WIDTH)
                .get()
                .addClickListener(this::handleGenerateJwtClick);
    }

    private void updateFakeIccid(TextBox deviceIdTextBox, TextBox iccidTextBox) {
        md5.reset();
        String iccid = bytesToHex(md5.digest(deviceIdTextBox.getStringValue().getBytes())).substring(0, ICCID_LENGTH);
        iccidTextBox.setValue(iccid);
    }

    private void handleGenerateJwtClick(Event evt) {
        Loader loader = Loader.create(jwtCodeCard, LoaderEffect.PULSE)
                .setLoadingText("Generating ...")
                .start();

        uiHandlers.requestJwt(loader, iccidBox.getStringValue(), expirationTimeMs);
    }

    @Override
    public void setUiHandlers(CreateAndValidateUiHandlers uiHandlers) {
        this.uiHandlers = uiHandlers;
    }

    @Override
    public void onJwtChanged(JwtResponse jwtResponse) {
        optionalJwtResponse = Optional.of(jwtResponse);
        validateJwtButton.show();

        String formattedToken = String.join("\n", splitEqually(optionalJwtResponse.get().token, 80));

        jwtCodeCard.setCode(formattedToken);
    }

    @Override
    public void onInvalidatedEvent() {
        invalidateJwt();
    }

    private void invalidateJwt() {
        optionalJwtResponse = Optional.empty();
        validateJwtButton.hide();
        jwtCodeCard.setCode("Not generated yet");
    }
}