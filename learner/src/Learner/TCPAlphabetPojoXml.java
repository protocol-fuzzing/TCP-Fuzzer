package Learner;

import io.github.protocolfuzzing.protocolstatefuzzer.components.learner.alphabet.xml.AlphabetPojoXml;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@XmlRootElement(name = "alphabet")
@XmlAccessorType(XmlAccessType.FIELD)
public class TCPAlphabetPojoXml extends AlphabetPojoXml<TCPInput> {

    @XmlAttribute(name = "payloadPattern")
    private String payloadPattern = "x";

    @XmlElements(
        value = { @XmlElement(type = TCPInputPojoXml.class, name = "TCPInput") }
    )
    private List<TCPInputPojoXml> xmlInputs;

    @XmlElement(name = "TCPInputFamily")
    private List<TCPInputFamilyPojoXml> xmlInputFamilies = 
        new ArrayList<>();

    public TCPAlphabetPojoXml() {
        xmlInputs = new ArrayList<>();
    }

    public List<TCPInput> getInputs() {
        List<TCPInput> allInputs = new ArrayList<>();

        for (TCPInputPojoXml xmlInput : xmlInputs) {
            String flags = xmlInput.flags != null
                ? xmlInput.flags
                : xmlInput.name;

            int payloadSize = xmlInput.payloadSize != null
                ? xmlInput.payloadSize
                : 0;

            allInputs.add(
                new TCPInput(
                    xmlInput.name,
                    flags,
                    payloadSize,
                    payloadPattern
                )
            );
        }

        for (TCPInputFamilyPojoXml family : xmlInputFamilies) {
            List<Integer> sizes = parsePayloadSizes(
                family.payloadSizes
            );

            for (int size : sizes) {
                allInputs.add(
                    new TCPInput(
                        family.name + "_" + size,
                        family.flags,
                        size,
                        payloadPattern
                    )
                );
            }
        }

        return allInputs;
    }

    private List<Integer> parsePayloadSizes(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(
                "payloadSizes cannot be empty"
            );
        }

        String trimmed = value.trim();

        // Handle one size, for example payloadSizes="3".
        if (!trimmed.contains("-")) {
            int size = Integer.parseInt(trimmed);

            if (size < 0) {
                throw new IllegalArgumentException(
                    "Payload size cannot be negative: " + size
                );
            }

            return List.of(size);
        }

        // Handle a range, for example payloadSizes="1-10".
        String[] parts = trimmed.split("-", 2);

        int minimum = Integer.parseInt(parts[0].trim());
        int maximum = Integer.parseInt(parts[1].trim());

        if (minimum < 0) {
            throw new IllegalArgumentException(
                "Minimum payload size cannot be negative: " + minimum
            );
        }

        if (maximum < minimum) {
            throw new IllegalArgumentException(
                "Maximum payload size must be greater than or equal to minimum"
            );
        }

        List<Integer> sizes = new ArrayList<>();

        for (int size = minimum; size <= maximum; size++) {
            sizes.add(size);
        }

        return sizes;
    }

    public static class TCPInputPojoXml {

        @XmlAttribute(name = "name", required = true)
        private String name;

        @XmlAttribute(name = "flags")
        private String flags;

        @XmlAttribute(name = "payloadSize")
        private Integer payloadSize;
    }

    public static class TCPInputFamilyPojoXml {

        @XmlAttribute(name = "name", required = true)
        private String name;

        @XmlAttribute(name = "flags", required = true)
        private String flags;

        @XmlAttribute(name = "payloadSizes", required = true)
        private String payloadSizes;
    }


}
