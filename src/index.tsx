// Quick access panel for the HotBar Decky plugin.
import { PanelSection, PanelSectionRow, staticClasses } from "@decky/ui";
import { definePlugin } from "@decky/api";
import { FaKeyboard } from "react-icons/fa";

function Content() {
  return (
    <PanelSection title="HotBar">
      <PanelSectionRow>
        <div>HotBar is not set up yet.</div>
      </PanelSectionRow>
    </PanelSection>
  );
}

export default definePlugin(() => {
  return {
    name: "HotBar",
    titleView: <div className={staticClasses.Title}>HotBar</div>,
    content: <Content />,
    icon: <FaKeyboard />,
  };
});
