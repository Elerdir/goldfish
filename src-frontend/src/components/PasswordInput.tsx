import { useState } from "react";
import type { ChangeEventHandler, KeyboardEventHandler } from "react";
import { Eye, EyeOff } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Input } from "@/components/ui/input";

interface PasswordInputProps {
    id: string;
    value: string;
    onChange: ChangeEventHandler<HTMLInputElement>;
    onKeyDown?: KeyboardEventHandler<HTMLInputElement>;
    placeholder?: string;
    autoFocus?: boolean;
    autoComplete?: string;
}

export function PasswordInput({
    id,
    value,
    onChange,
    onKeyDown,
    placeholder,
    autoFocus,
    autoComplete = "current-password",
}: PasswordInputProps) {
    const { t } = useTranslation();
    const [visible, setVisible] = useState(false);

    return (
        <div className="relative">
            <Input
                id={id}
                type={visible ? "text" : "password"}
                value={value}
                onChange={onChange}
                onKeyDown={onKeyDown}
                placeholder={placeholder}
                autoFocus={autoFocus}
                autoComplete={autoComplete}
                spellCheck={false}
                className="pr-10"
            />
            <button
                type="button"
                tabIndex={-1}
                onClick={() => setVisible((v) => !v)}
                aria-label={visible ? t("common.hide") : t("common.show")}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
                {visible ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
        </div>
    );
}
