#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::NativeOptions;

pub mod ui;

fn main() -> anyhow::Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_BACKTRACE", "1");

    eframe::run_native(
        "Task Manager",
        {
            NativeOptions {
                
                ..Default::default()
            }
        },
        Box::new(|cc| Box::new(ui::app::TaskManager::new(cc))),
    )?;

    Ok(())
}

/*  Gulyásleves recipe

    Heat the oil or lard in a large pot (preferably a Dutch oven). Add the onions along with a few spoonfuls of water (so they don’t brown) and a pinch of the salt. Cook slowly over very low heat for about 15 to 20 minutes, or until the onions are clear and glassy.
    Remove from the heat and add the paprika, pepper, and caraway seeds. Stir quickly to combine and add a tiny bit of water (to prevent the paprika from burning).
    Add the meat and garlic and cook over high heat, stirring, until the meat is slightly browned (about ten minutes). Turn the heat down to low, add a few spoonfuls of water, and cook for about 15 more minutes, until the meat is nearly cooked through.
    Add the rest of the water and keep cooking, over low heat, for at least an hour, or until the meat is cooked and nearly tender enough to serve. This could take hours, depending on the cut of beef you used.
    When the meat is nearly done, add the tomatoes, carrots, parsnips, and potatoes and cook for about 15 more minutes, or until they are tender (being careful not to overcook them). Taste the soup and add more salt and pepper, if needed.
    If you are using csipetke or another kind of small pasta, add it to the soup before serving. You can serve this soup with hot pepper or hot pepper paste.

*/
